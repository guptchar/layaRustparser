use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::parser::UniversalParser;
use crate::schema::ocsf::NetworkActivity;

/// Configuration for Syslog Ingestion Sockets
#[derive(Debug, Clone)]
pub struct IngestConfig {
    pub bind_addr: SocketAddr,
    pub reuse_port: bool,
    pub batch_size: usize,
    pub batch_timeout: Duration,
    pub buffer_capacity: usize,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:514".parse().unwrap(),
            reuse_port: true,
            batch_size: 1000,
            batch_timeout: Duration::from_millis(50),
            buffer_capacity: 65536,
        }
    }
}

/// SO_RCVBUF requested on every ingest socket (UDP + TCP listener).
///
/// The kernel default on this machine class is ~208 KiB (212,992 bytes as
/// reported by getsockopt, which doubles the real allocation for
/// bookkeeping). At burst rates the socket task cannot drain a 208 KiB
/// buffer fast enough and the kernel drops datagrams before userspace
/// ever sees them — docs/INGEST_LIMITS.md has the measured knee.
/// 4 MiB fits under the usual rmem_max (4,194,304) so an unprivileged
/// set succeeds; where a machine caps lower, Linux clamps silently and
/// the ingest banner reports the effective value, so the operator never
/// has to guess which buffer they got.
pub const INGEST_RCVBUF_BYTES: usize = 4 * 1024 * 1024;

/// Create a non-blocking UDP socket with SO_REUSEPORT and SO_REUSEADDR enabled
pub fn create_udp_socket(addr: SocketAddr, reuse_port: bool) -> io::Result<UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;

    #[cfg(all(unix, not(target_os = "solaris")))]
    if reuse_port {
        socket.set_reuse_port(true)?;
    }

    // Best-effort: a clamped or default buffer still ingests, just with a
    // lower burst ceiling. The ingest banner prints the effective value
    // (see udp_socket_rcvbuf), so a silent clamp stays visible.
    let _ = socket.set_recv_buffer_size(INGEST_RCVBUF_BYTES);

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

/// Effective SO_RCVBUF of a bound UDP socket, as reported by the kernel.
/// Linux doubles the requested value for bookkeeping — compare
/// getsockopt-to-getsockopt, not to /proc/sys/net/core/rmem_default.
pub fn udp_socket_rcvbuf(socket: &UdpSocket) -> io::Result<usize> {
    socket2::SockRef::from(socket).recv_buffer_size()
}

/// Create a non-blocking TCP listener with SO_REUSEPORT and SO_REUSEADDR enabled
pub fn create_tcp_listener(
    addr: SocketAddr,
    reuse_port: bool,
    backlog: i32,
) -> io::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;

    #[cfg(all(unix, not(target_os = "solaris")))]
    if reuse_port {
        socket.set_reuse_port(true)?;
    }

    // Same best-effort tuning as UDP. On Linux an accepted stream
    // inherits the listener's receive buffer, so this one call covers
    // every connection the listener hands out.
    let _ = socket.set_recv_buffer_size(INGEST_RCVBUF_BYTES);

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(backlog)?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

/// Effective SO_RCVBUF of a bound TCP listener, as reported by the kernel.
/// Accepted streams inherit this buffer on Linux.
pub fn tcp_listener_rcvbuf(listener: &TcpListener) -> io::Result<usize> {
    socket2::SockRef::from(listener).recv_buffer_size()
}

/// Capacity of the internal socket-to-parser channel in
/// [`UdpSyslogListener::run_parsed`], in batches. Sized to absorb a brief
/// parser stall in the queue rather than by shedding.
const RAW_BATCH_CHANNEL: usize = 8;

/// Aborts a spawned task on drop, but lets a caller await it first.
///
/// Used for the receive task inside [`UdpSyslogListener::run_parsed`]. The
/// `JoinHandle` has to be retained so a normal exit can await the task and
/// surface its error; without a drop guard, every early return would detach
/// a task still parked in `recv_from`, holding the bound socket open for the
/// life of the process.
struct AbortOnDrop<T>(Option<tokio::task::JoinHandle<T>>);

impl AbortOnDrop<anyhow::Result<()>> {
    /// Await the task, propagating a panic as an error.
    ///
    /// Takes `&mut self` rather than `self`: the type implements `Drop`, so
    /// the handle cannot be moved out. Taking the inner `Option` leaves the
    /// drop guard inert afterwards, so the task is never aborted after being
    /// properly awaited.
    ///
    /// Only valid once the task is known to have finished. For a task still
    /// parked in `recv_from` this would block forever — call
    /// [`AbortOnDrop::abort`] first, which is why the early-exit path below
    /// does exactly that.
    async fn finish(&mut self) -> anyhow::Result<()> {
        match self.0.take() {
            Some(handle) => match handle.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) if e.is_panic() => Err(anyhow::anyhow!("receive task panicked: {e}")),
                // Aborted: the loop below decided to stop. Not a failure.
                Err(_) => Ok(()),
            },
            None => Ok(()),
        }
    }

    /// Stop the task now, so a subsequent [`AbortOnDrop::finish`] can join it
    /// instead of waiting on a recv that will never return.
    fn abort(&mut self) {
        if let Some(handle) = self.0.as_ref() {
            handle.abort();
        }
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.0.as_ref() {
            handle.abort();
        }
    }
}

/// Point-in-time view of a [`BatchSender`] handoff channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChannelStats {
    /// Batches currently queued (excludes the batch a producer is building).
    pub depth: usize,
    /// Channel capacity in batches, as reported by the channel itself.
    pub capacity: usize,
    pub sent_batches: u64,
    pub sent_lines: u64,
    /// Batches shed because the channel was full (drop-newest policy).
    pub dropped_batches: u64,
    /// Lines lost with those shed batches.
    pub dropped_lines: u64,
}

/// Shared counters for a [`BatchSender`]. Cloning is a refcount bump, so a
/// caller can hold one handle and poll it while the sender is owned by a
/// spawned recv task.
#[derive(Debug, Clone, Default)]
pub struct BatchChannelStats(Arc<BatchChannelCounters>);

#[derive(Debug, Default)]
struct BatchChannelCounters {
    sent_batches: AtomicU64,
    sent_lines: AtomicU64,
    dropped_batches: AtomicU64,
    dropped_lines: AtomicU64,
    /// Batches currently in the channel.
    ///
    /// Tracked explicitly rather than read back from the `mpsc::Sender`.
    /// Holding a sender clone to query `capacity()` would keep the channel
    /// open: `Receiver::recv` would never observe the sender count reaching
    /// zero, so the recv loops would spin forever instead of terminating.
    /// The producer increments on a successful send and the consumer
    /// decrements via [`BatchSender::record_received`].
    depth: AtomicUsize,
    /// Channel capacity in batches, recorded when the sender is built.
    capacity: AtomicUsize,
}

impl BatchChannelStats {
    fn record_sent(&self, lines: usize) {
        self.0.sent_batches.fetch_add(1, Ordering::Relaxed);
        self.0.sent_lines.fetch_add(lines as u64, Ordering::Relaxed);
    }

    fn record_dropped(&self, lines: usize) {
        self.0.dropped_batches.fetch_add(1, Ordering::Relaxed);
        self.0
            .dropped_lines
            .fetch_add(lines as u64, Ordering::Relaxed);
    }

    /// Note that the consumer took `batches` batches off the channel.
    ///
    /// Callers draining a [`BatchSender`]'s channel must call this so the
    /// reported `depth` gauge stays honest — it is tracked explicitly rather
    /// than read back from the sender, because holding a sender clone to
    /// query it would stop `Receiver::recv` from ever seeing the sender count
    /// reach zero and the recv loops would never terminate.
    pub fn record_received(&self, batches: usize) {
        self.0.depth.fetch_sub(batches, Ordering::Relaxed);
    }

    /// Live gauges plus cumulative counters.
    pub fn counters(&self) -> ChannelStats {
        ChannelStats {
            sent_batches: self.0.sent_batches.load(Ordering::Relaxed),
            sent_lines: self.0.sent_lines.load(Ordering::Relaxed),
            dropped_batches: self.0.dropped_batches.load(Ordering::Relaxed),
            dropped_lines: self.0.dropped_lines.load(Ordering::Relaxed),
            depth: self.0.depth.load(Ordering::Relaxed),
            capacity: self.0.capacity.load(Ordering::Relaxed),
        }
    }
}

/// Bounded, non-blocking batch handoff from a recv task to its consumer.
///
/// **Backpressure policy: drop-newest.** When the channel is full the
/// *incoming* batch is shed and counted, and the recv loop keeps going.
///
/// The alternative — parking the producer until the consumer drains — was
/// rejected on purpose. A blocked recv loop stops draining the kernel socket
/// buffer, so the kernel starts dropping datagrams we never see and never
/// count. Shedding in userspace at least keeps the loss bounded, attributed,
/// and visible in `dropped_lines`. The line-rate ingest path must never stall
/// on a slow parser (see the zero-copy and backpressure invariants in
/// `AGENTS.md`).
pub struct BatchSender<T> {
    tx: mpsc::Sender<Vec<T>>,
    batch_size: usize,
    stats: BatchChannelStats,
}

/// Clones share one channel and one set of counters. Handwritten rather than
/// derived because `T` itself is not `Clone` — a `Vec<Bytes>` handoff clones
/// the channel handle, never a batch.
impl<T> Clone for BatchSender<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            batch_size: self.batch_size,
            stats: self.stats.clone(),
        }
    }
}

impl<T: Send + 'static> BatchSender<T> {
    /// Wrap an existing bounded channel. `batch_size` pre-allocates each
    /// outgoing batch; `tx` carries the real capacity.
    pub fn new(tx: mpsc::Sender<Vec<T>>, batch_size: usize) -> Self {
        Self::with_stats(tx, batch_size, BatchChannelStats::default())
    }

    /// Like [`BatchSender::new`], but writing into caller-owned counters.
    ///
    /// [`UdpSyslogListener::run_parsed`] builds its socket-to-parser hop
    /// internally, so this is how a caller keeps a handle on the receive
    /// side's drop counters while that hop runs inside the method.
    pub fn with_stats(
        tx: mpsc::Sender<Vec<T>>,
        batch_size: usize,
        stats: BatchChannelStats,
    ) -> Self {
        // Capacity is fixed at construction, so record it once. `store` rather
        // than `fetch_max`: a handle may be shared across senders, and the
        // first writer holds the authoritative value.
        let capacity = tx.max_capacity();
        let _ =
            stats
                .0
                .capacity
                .compare_exchange(0, capacity, Ordering::Relaxed, Ordering::Relaxed);
        Self {
            tx,
            batch_size,
            stats,
        }
    }

    /// An independent handle for polling counters from elsewhere.
    pub fn stats(&self) -> BatchChannelStats {
        self.stats.clone()
    }

    /// Resolves once the consumer is gone, so a producer can shut down
    /// promptly instead of waiting for its next batch to fail to send.
    pub async fn closed(&self) {
        self.tx.closed().await
    }

    /// Empty batch buffer sized for the next flush, avoiding a realloc on
    /// every batch boundary.
    pub fn empty_batch(&self) -> Vec<T> {
        Vec::with_capacity(self.batch_size)
    }

    /// Try to hand off one batch without ever blocking the caller.
    ///
    /// Returns `false` only when the consumer is gone (receiver dropped),
    /// which is the signal to shut the recv loop down. A *full* channel is
    /// not a shutdown: the batch is shed, counted, and `true` is returned.
    pub fn send_batch(&self, batch: Vec<T>) -> bool {
        let lines = batch.len();
        // Publish the depth *before* the send, not after. A consumer can wake
        // and drain the instant `try_send` succeeds, so incrementing afterwards
        // leaves a window where a consumer already decremented a depth this
        // counter has not raised — the gauge would read one too low, and the
        // subsequent `record_received` could underflow the unsigned counter.
        // Rolling back on failure keeps the two paths balanced.
        self.stats.0.depth.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(batch) {
            Ok(()) => {
                self.stats.record_sent(lines);
                true
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.stats.record_dropped(lines);
                self.stats.0.depth.fetch_sub(1, Ordering::Relaxed);
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.stats.0.depth.fetch_sub(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Await handoff of one batch, applying real backpressure.
    ///
    /// **Reliable transports only** (see [`TcpSyslogListener::run_raw`]). When
    /// the channel is full this parks until the consumer drains a slot. That
    /// is safe precisely because the transport is reliable: the reader stops
    /// pulling from the stream, the TCP receive window fills, and the kernel
    /// throttles the sender. The client is never told a line was discarded,
    /// because none was — it just waits.
    ///
    /// Counting stays symmetric with [`BatchSender::send_batch`]: a delivered
    /// batch counts as sent, and `false` means the consumer is gone.
    pub async fn send_batch_async(&self, batch: Vec<T>) -> bool {
        let lines = batch.len();
        // Same ordering rule as `send_batch`: raise depth before the batch can
        // become visible, roll back if it never lands.
        self.stats.0.depth.fetch_add(1, Ordering::Relaxed);
        match self.tx.send(batch).await {
            Ok(()) => {
                self.stats.record_sent(lines);
                true
            }
            // The receiver dropped while we were parked, so the batch was
            // never enqueued. There is no consumer left to shed it to — this
            // is a shutdown, not a loss to count.
            Err(_) => {
                self.stats.0.depth.fetch_sub(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Live gauges plus counters, for a stats line alongside EPS.
    ///
    /// Reads the shared counters, so this is equivalent to calling
    /// [`BatchSender::stats`]`::counters()` — both surfaces report the same
    /// `depth` and `capacity`.
    ///
    /// `depth` is maintained explicitly by the send/receive pair rather than
    /// sampled from the `Sender`, so a concurrent send can race the read. Treat
    /// it as a gauge, not an exact count.
    pub fn snapshot(&self) -> ChannelStats {
        self.stats.counters()
    }
}

/// High-throughput UDP Syslog listener
pub struct UdpSyslogListener {
    socket: UdpSocket,
    config: IngestConfig,
}

impl UdpSyslogListener {
    pub fn bind(config: IngestConfig) -> io::Result<Self> {
        let socket = create_udp_socket(config.bind_addr, config.reuse_port)?;
        Ok(Self { socket, config })
    }

    pub fn from_socket(socket: UdpSocket, config: IngestConfig) -> Self {
        Self { socket, config }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Run the UDP packet receiver and forward batches of raw lines as
    /// [`Bytes`] to a bounded channel.
    ///
    /// `Bytes` is refcount-shared, so a consumer that fans a line out to more
    /// than one place pays a refcount bump instead of a payload copy. One copy
    /// at the datagram boundary is unavoidable: the recv buffer is reused for
    /// the next datagram, so each line must be lifted into its own allocation
    /// to outlive this iteration.
    pub async fn run_raw(self, sink: BatchSender<Bytes>) -> anyhow::Result<()> {
        self.pump(sink).await
    }

    /// Run the UDP packet receiver, parsing with [`UniversalParser`] and
    /// forwarding normalized OCSF events onward.
    ///
    /// **Parsing deliberately does not happen on the receive loop.** The
    /// receive side runs in its own task via [`UdpSyslogListener::run_raw`],
    /// handing raw batches onward without ever blocking. Only this task
    /// parses. If `parse_lossless` were called inline on the receive loop, a
    /// parser slower than the arrival rate would delay the next `recv_from`,
    /// the kernel would start dropping datagrams, and those drops would be
    /// invisible: `send_batch` has not run yet, so no counter could record
    /// them. Keeping the receive loop doing nothing but receiving is what
    /// makes the shed accounting complete.
    ///
    /// Both hops are bounded and non-blocking, so the two loss points stay
    /// distinct and separately counted: `recv_stats` accounts for batches
    /// shed between socket and parser, `sink` for those shed after parsing.
    /// The caller owns `recv_stats` so it can poll receive-side counters from
    /// another task while this one is running.
    pub async fn run_parsed(
        self,
        parser: Arc<UniversalParser>,
        sink: BatchSender<NetworkActivity>,
        recv_stats: BatchChannelStats,
    ) -> anyhow::Result<()> {
        let (raw_tx, mut raw_rx) = mpsc::channel::<Vec<Bytes>>(RAW_BATCH_CHANNEL);
        // Keep a handle so the receive-side depth gauge can be decremented as
        // batches are drained below.
        let recv_gauge = recv_stats.clone();
        let raw_sink = BatchSender::with_stats(raw_tx, self.config.batch_size, recv_stats);

        // Hold the receive task's handle rather than detaching it. If the
        // output consumer goes away, the loop below breaks early and this
        // method returns while the receive task is still blocked in
        // `recv_from`, holding the bound socket open. Detaching would strand
        // it for the life of the process. The guard aborts on drop, so every
        // exit path below tears the task down.
        let mut raw_task = AbortOnDrop(Some(tokio::spawn(
            async move { self.run_raw(raw_sink).await },
        )));

        loop {
            // Race the next batch against the consumer disappearing. Without
            // the `closed()` arm, a vanished consumer is only noticed when the
            // *next* batch fails to send — so on a quiet socket this task
            // would sit in `recv()` forever, holding the receive task and its
            // bound socket for the life of the process.
            let raw_batch = tokio::select! {
                batch = raw_rx.recv() => match batch {
                    Some(batch) => batch,
                    // Receive side ended on its own.
                    None => break,
                },
                _ = sink.closed() => {
                    // Consumer is gone: nothing downstream can receive output.
                    // Stop the receive task explicitly — it is parked in
                    // `recv_from` and will never return on its own, so
                    // awaiting it without aborting first would hang here.
                    raw_task.abort();
                    break;
                }
            };

            // This batch has left the receive channel, so drop it from the
            // receive-side depth gauge.
            recv_gauge.record_received(1);

            let mut parsed_batch = Vec::with_capacity(raw_batch.len());
            for raw_line in raw_batch {
                // These bytes were validated as UTF-8 when the datagram was
                // decoded, so this is a borrow of the same allocation.
                match std::str::from_utf8(&raw_line) {
                    Ok(text) => parsed_batch.push(parser.parse_lossless(text)),
                    Err(_) => tracing::warn!("skipping non-UTF-8 line in raw batch"),
                }
            }
            if !sink.send_batch(parsed_batch) {
                // Consumer vanished between the select and now. Same deadlock
                // as the `closed()` arm: abort before awaiting. The send never
                // enqueued, so there is nothing to subtract from the output
                // depth gauge.
                raw_task.abort();
                break;
            }
        }

        // `recv()` returned `None`, so the receive task has already dropped
        // its sender and finished on its own. Await it to surface a genuine
        // receive-side error rather than swallowing it. If the loop broke
        // early because the consumer vanished, the guard aborts instead.
        raw_task.finish().await
    }

    /// Shared UDP recv loop: decode each datagram into a batch of [`Bytes`]
    /// and flush on size or timeout. Deliberately mapping-free — this is the
    /// loop that must not do work proportional to the parser.
    async fn pump(self, sink: BatchSender<Bytes>) -> anyhow::Result<()> {
        let mut buf = vec![0u8; self.config.buffer_capacity];
        let mut current_batch = sink.empty_batch();
        let mut last_flush = tokio::time::Instant::now();

        loop {
            tokio::select! {
                res = self.socket.recv_from(&mut buf) => {
                    match res {
                        Ok((size, _peer)) => {
                            let payload = &buf[..size];
                            if let Ok(text) = std::str::from_utf8(payload) {
                                for line in text.lines() {
                                    let trimmed = line.trim();
                                    if !trimmed.is_empty() {
                                        current_batch.push(Bytes::copy_from_slice(trimmed.as_bytes()));
                                        if current_batch.len() >= self.config.batch_size {
                                            let batch = std::mem::replace(&mut current_batch, sink.empty_batch());
                                            if !sink.send_batch(batch) {
                                                return Ok(());
                                            }
                                            last_flush = tokio::time::Instant::now();
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("UDP recv_from error: {:?}", e);
                        }
                    }
                }
                _ = sleep(self.config.batch_timeout) => {
                    if !current_batch.is_empty() && last_flush.elapsed() >= self.config.batch_timeout {
                        let batch = std::mem::replace(&mut current_batch, sink.empty_batch());
                        if !sink.send_batch(batch) {
                            return Ok(());
                        }
                        last_flush = tokio::time::Instant::now();
                    }
                }
            }
        }
    }
}

/// High-throughput TCP Syslog listener
pub struct TcpSyslogListener {
    listener: TcpListener,
    config: IngestConfig,
}

impl TcpSyslogListener {
    pub fn bind(config: IngestConfig) -> io::Result<Self> {
        let listener = create_tcp_listener(config.bind_addr, config.reuse_port, 1024)?;
        Ok(Self { listener, config })
    }

    pub fn from_listener(listener: TcpListener, config: IngestConfig) -> Self {
        Self { listener, config }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run TCP connection acceptor, spawning connection reader tasks
    ///
    /// One [`BatchSender`] is shared by every connection, so the depth and
    /// drop counters describe the transport as a whole rather than per
    /// connection.
    ///
    /// **Delivery semantics: no silent loss.** Batches are handed off with
    /// [`BatchSender::send_batch_async`], which awaits rather than sheds. TCP
    /// differs from UDP here in a way that matters: shedding a batch the
    /// client already delivered would discard data the sender has no way to
    /// learn was lost — it gets no error, and TCP considers delivery complete.
    /// Awaiting instead stops the reader, fills the receive window, and lets
    /// the kernel throttle the sender, so a slow consumer becomes
    /// backpressure rather than data loss. This preserves the pre-`Bytes`
    /// await behavior deliberately, unlike the UDP path which does shed.
    ///
    /// The cost is that a stalled consumer can park a connection task. That
    /// is the intended trade on a reliable transport.
    pub async fn run_raw(self, sink: BatchSender<Bytes>) -> anyhow::Result<()> {
        let batch_size = self.config.batch_size;
        let batch_timeout = self.config.batch_timeout;

        loop {
            match self.listener.accept().await {
                Ok((stream, _peer)) => {
                    let sink_conn = sink.clone();
                    tokio::spawn(async move {
                        let reader = BufReader::new(stream);
                        let mut lines = reader.lines();
                        let mut batch = sink_conn.empty_batch();
                        let mut last_flush = tokio::time::Instant::now();

                        while let Ok(Some(line)) = lines.next_line().await {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() {
                                // `lines()` already produced an owned `String`.
                                // When nothing needs trimming, hand that exact
                                // allocation to `Bytes` instead of copying it
                                // into a second one — the common case on the
                                // wire, and the whole point of the change.
                                // Trimming in the middle can only copy, so it
                                // falls back to a single `copy_from_slice`.
                                batch.push(if line.len() == trimmed.len() {
                                    Bytes::from(line)
                                } else {
                                    Bytes::copy_from_slice(trimmed.as_bytes())
                                });
                                if batch.len() >= batch_size
                                    || last_flush.elapsed() >= batch_timeout
                                {
                                    let to_send =
                                        std::mem::replace(&mut batch, sink_conn.empty_batch());
                                    if !sink_conn.send_batch_async(to_send).await {
                                        break;
                                    }
                                    last_flush = tokio::time::Instant::now();
                                }
                            }
                        }

                        // Tail flush on disconnect. Awaited like every other
                        // handoff here, so a client that sent its last line
                        // and closed still has that line delivered.
                        if !batch.is_empty() {
                            sink_conn.send_batch_async(batch).await;
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("TCP accept error: {:?}", e);
                }
            }
        }
    }
}

/// Counters for one worker's two bounded hops.
#[derive(Debug, Clone)]
pub struct UdpWorkerStats {
    /// Socket-to-parser hop. Drops here mean the parser could not keep up.
    pub recv: BatchChannelStats,
    /// Parser-to-consumer hop. Drops here mean the consumer could not keep up.
    pub out: BatchChannelStats,
}

impl UdpWorkerStats {
    /// Total lines shed across both hops. Tracked separately because the two
    /// mean different things operationally: `recv` sheds are parser lag,
    /// `out` sheds are downstream saturation.
    pub fn total_dropped_lines(&self) -> u64 {
        self.recv.counters().dropped_lines + self.out.counters().dropped_lines
    }
}

/// Handles and per-worker counters for a [`spawn_udp_worker_pool`] pool.
pub struct UdpWorkerPool {
    /// Join handles for the spawned recv tasks, in worker order.
    pub handles: Vec<tokio::task::JoinHandle<()>>,
    /// Counter handles matching `handles` index-for-index. Each worker owns
    /// its own, so a stalled worker stays visible instead of hiding behind a
    /// pool-wide total.
    pub stats: Vec<UdpWorkerStats>,
}

/// Spawns a multi-worker UDP listener pool using SO_REUSEPORT across worker threads
pub fn spawn_udp_worker_pool(
    config: IngestConfig,
    num_workers: usize,
    parser: Arc<UniversalParser>,
    tx: mpsc::Sender<Vec<NetworkActivity>>,
) -> io::Result<UdpWorkerPool> {
    let mut handles = Vec::with_capacity(num_workers);
    let mut stats = Vec::with_capacity(num_workers);

    for _ in 0..num_workers {
        let listener = UdpSyslogListener::bind(config.clone())?;
        let parser_clone = Arc::clone(&parser);
        let batch_size = config.batch_size;
        let sink = BatchSender::new(tx.clone(), batch_size);
        let recv_stats = BatchChannelStats::default();
        stats.push(UdpWorkerStats {
            recv: recv_stats.clone(),
            out: sink.stats(),
        });

        let handle = tokio::spawn(async move {
            let _ = listener.run_parsed(parser_clone, sink, recv_stats).await;
        });

        handles.push(handle);
    }

    Ok(UdpWorkerPool { handles, stats })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_so_reuseport_udp_creation() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket1 = create_udp_socket(addr, true).unwrap();
        let local_port = socket1.local_addr().unwrap().port();

        // Bind another socket to the same local port using SO_REUSEPORT
        let target_addr: SocketAddr = format!("127.0.0.1:{}", local_port).parse().unwrap();
        let socket2 = create_udp_socket(target_addr, true);
        assert!(socket2.is_ok(), "SO_REUSEPORT binding should succeed");
    }

    #[tokio::test]
    async fn test_ingest_sockets_request_tuned_rcvbuf() {
        // create_*_socket must apply INGEST_RCVBUF_BYTES. The kernel
        // reports double the allocation for bookkeeping and may clamp to
        // rmem_max, so instead of asserting an absolute number, compare
        // against a probe socket given the identical request on the same
        // machine: same request, same clamp, same readback.
        let probe = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        let stock = probe.recv_buffer_size().unwrap();
        probe.set_recv_buffer_size(INGEST_RCVBUF_BYTES).unwrap();
        let expected = probe.recv_buffer_size().unwrap();
        assert!(
            expected >= stock,
            "probe sanity: requesting {INGEST_RCVBUF_BYTES} must not shrink the buffer"
        );

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let tuned = create_udp_socket(addr, false).unwrap();
        let got = udp_socket_rcvbuf(&tuned).unwrap();
        assert_eq!(
            got, expected,
            "create_udp_socket must request INGEST_RCVBUF_BYTES ({INGEST_RCVBUF_BYTES})"
        );

        let listener = create_tcp_listener(addr, false, 16).unwrap();
        let tcp_got = tcp_listener_rcvbuf(&listener).unwrap();
        assert!(
            tcp_got >= stock,
            "tuned TCP rcvbuf ({tcp_got}) must be >= stock default ({stock})"
        );
    }

    #[tokio::test]
    async fn test_udp_ingest_pipeline() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut config = IngestConfig::default();
        config.bind_addr = addr;
        config.batch_size = 2;
        config.batch_timeout = Duration::from_millis(10);

        let listener = UdpSyslogListener::bind(config).unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let (tx, mut rx) = mpsc::channel(10);
        let parser = Arc::new(UniversalParser::new());
        let sink = BatchSender::new(tx, 2);

        let server_handle = tokio::spawn(async move {
            let _ = listener
                .run_parsed(parser, sink, BatchChannelStats::default())
                .await;
        });

        // Send test UDP packet
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let log_line = "%ASA-6-302013: Built inbound UDP connection 123 for outside:1.1.1.1/53 to inside:2.2.2.2/53\n";
        sender
            .send_to(log_line.as_bytes(), actual_addr)
            .await
            .unwrap();

        let received = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;
        assert!(received.is_ok(), "Should receive batch within timeout");
        let batch = received.unwrap().expect("Batch was None");
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].src_endpoint.ip.as_deref(), Some("1.1.1.1"));

        server_handle.abort();
    }

    /// The whole point of the `Bytes` switch: a line must survive the trip
    /// byte-for-byte, because `raw_log` is the lossless-provenance anchor.
    /// Guards against a trim or slice regression quietly altering payloads.
    #[tokio::test]
    async fn test_run_raw_delivers_bytes_verbatim() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut config = IngestConfig::default();
        config.bind_addr = addr;
        config.batch_size = 8;
        config.batch_timeout = Duration::from_millis(10);

        let listener = UdpSyslogListener::bind(config).unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let (tx, mut rx) = mpsc::channel(10);
        let sink = BatchSender::new(tx, 8);
        let stats = sink.stats();

        let server = tokio::spawn(async move {
            let _ = listener.run_raw(sink).await;
        });

        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // A multi-line datagram with deliberate leading/trailing padding,
        // an interior tab that must survive, and a blank line that must be
        // filtered out. `trim` strips surrounding whitespace only, so the
        // interior tab inside the second line has to come through intact.
        let payload = "  first line  \n\n\tsecond\tline\t\nthird line\n";
        sender
            .send_to(payload.as_bytes(), actual_addr)
            .await
            .unwrap();

        let batch = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("batch within timeout")
            .expect("channel open");

        let got: Vec<String> = batch
            .iter()
            .map(|b| String::from_utf8(b.to_vec()).expect("valid utf-8"))
            .collect();
        assert_eq!(
            got,
            vec!["first line", "second\tline", "third line"],
            "surrounding whitespace trimmed, interior whitespace preserved, order kept"
        );

        let counters = stats.counters();
        assert_eq!(counters.sent_lines, 3, "blank line must not be counted");
        assert_eq!(counters.dropped_lines, 0);

        server.abort();
    }

    /// A full channel must shed the incoming batch and keep counting, never
    /// park the producer. This is the invariant that keeps a slow consumer
    /// from stalling the recv loop back into kernel-level drops.
    #[tokio::test]
    async fn test_full_channel_sheds_instead_of_blocking() {
        let (tx, mut rx) = mpsc::channel(1);
        let sink = BatchSender::new(tx, 2);
        let stats = sink.stats();

        // Fill the single-slot channel; nothing drains it during this test.
        assert!(sink.send_batch(vec![Bytes::from("a"), Bytes::from("b")]));
        assert_eq!(stats.counters().sent_batches, 1);

        // Shed two more batches. Each must report "keep going" (true) — a
        // full channel is not a shutdown signal.
        assert!(
            sink.send_batch(vec![Bytes::from("c")]),
            "a full channel must not be treated as consumer-gone"
        );
        assert!(
            sink.send_batch(vec![Bytes::from("d"), Bytes::from("e")]),
            "recv loop must keep running after shedding"
        );

        let counters = stats.counters();
        assert_eq!(counters.dropped_batches, 2);
        assert_eq!(
            counters.dropped_lines, 3,
            "shedding accounts for every line"
        );
        assert_eq!(counters.sent_batches, 1, "shedding never inflates sent");

        // The one batch that did land is intact and first-in-first-out.
        let landed = rx.recv().await.expect("first batch present");
        assert_eq!(landed.len(), 2);

        let snap = stats.counters();
        assert_eq!(snap.sent_batches, 1, "no double counting on re-read");
    }

    /// A dropped receiver is the one case that must stop the loop.
    #[tokio::test]
    async fn test_closed_channel_signals_shutdown() {
        let (tx, rx) = mpsc::channel(4);
        let sink = BatchSender::new(tx, 2);
        drop(rx);
        assert!(
            !sink.send_batch(vec![Bytes::from("a")]),
            "send_batch must return false once the consumer is gone"
        );
        assert_eq!(stats_zero(&sink), 0);
    }

    fn stats_zero(sink: &BatchSender<Bytes>) -> u64 {
        sink.stats().counters().dropped_batches
    }

    /// Clones must share counters and channel, not fork them.
    #[tokio::test]
    async fn test_batch_sender_clone_shares_counters() {
        let (tx, _rx) = mpsc::channel(4);
        let sink = BatchSender::new(tx, 2);
        let clone = sink.clone();

        sink.send_batch(vec![Bytes::from("a")]);
        clone.send_batch(vec![Bytes::from("b"), Bytes::from("c")]);

        let counters = sink.stats().counters();
        assert_eq!(counters.sent_batches, 2, "clone shares the same counters");
        assert_eq!(counters.sent_lines, 3);
    }

    /// `snapshot()` must report the live channel gauges, not stale zeros —
    /// this is what a stats line alongside EPS would print.
    #[tokio::test]
    async fn test_snapshot_reports_depth_and_capacity() {
        let (tx, _rx) = mpsc::channel(4);
        let sink = BatchSender::new(tx, 2);

        let empty = sink.snapshot();
        assert_eq!(empty.depth, 0);
        assert_eq!(empty.capacity, 4);

        sink.send_batch(vec![Bytes::from("a"), Bytes::from("b")]);
        sink.send_batch(vec![Bytes::from("c")]);

        let busy = sink.snapshot();
        assert_eq!(busy.depth, 2, "two batches are queued");
        assert_eq!(busy.sent_batches, 2);
    }

    /// Regression guard for the review finding that pushed parsing off the
    /// receive loop.
    ///
    /// `run_parsed` must keep the socket read on its own task. If parsing were
    /// inlined into the receive loop, a slow parser would delay `recv_from`,
    /// the kernel would drop datagrams, and the counters would report zero
    /// drops while data silently vanished — the exact invisible-loss failure
    /// this design exists to prevent.
    ///
    /// Observable proxy: stall the output channel so the parse task is forced
    /// to park, then confirm the receive-side hop keeps draining the socket on
    /// its own. Receive-side counters must still climb while output is stalled.
    #[tokio::test]
    async fn test_receive_loop_drains_while_parser_is_stalled() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut config = IngestConfig::default();
        config.bind_addr = addr;
        config.batch_size = 1;
        config.batch_timeout = Duration::from_millis(5);

        let listener = UdpSyslogListener::bind(config).unwrap();
        let actual_addr = listener.local_addr().unwrap();

        // Output capacity 1 and nothing drains it: the parse task parks almost
        // immediately, so only an independent recv loop can keep up.
        let (tx, _rx) = mpsc::channel(1);
        let sink = BatchSender::new(tx, 1);
        let recv_stats = BatchChannelStats::default();
        let recv_handle = recv_stats.clone();

        let parser = Arc::new(UniversalParser::new());
        let server = tokio::spawn(async move {
            let _ = listener.run_parsed(parser, sink, recv_stats).await;
        });

        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let line = "%ASA-6-302013: Built outbound TCP connection 1000672 for outside:203.0.113.54/25 to inside:10.1.6.180/52369\n";
        for _ in 0..20 {
            let _ = sender.send_to(line.as_bytes(), actual_addr).await;
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
        let recv_counters = recv_handle.counters();

        assert!(
            recv_counters.sent_lines > 0,
            "receive-side hop must keep draining the socket while the parser is stalled"
        );

        server.abort();
    }

    /// TCP must not shed. Unlike UDP, a batch the client already delivered
    /// cannot be discarded without the client having any way to learn it was
    /// lost. `send_batch_async` must park instead of dropping.
    #[tokio::test]
    async fn test_async_send_waits_instead_of_shedding() {
        let (tx, mut rx) = mpsc::channel(1);
        let sink = BatchSender::new(tx, 2);
        let stats = sink.stats();

        // Occupy the single slot.
        assert!(sink.send_batch_async(vec![Bytes::from("first")]).await);

        // This one has nowhere to go until the consumer drains. Park it in a
        // task rather than timing it out inline: cancelling a live `send`
        // future strands its slot permit in tokio's mpsc, which would wedge
        // the channel instead of testing backpressure.
        let parked = tokio::spawn({
            let sink = sink.clone();
            async move {
                sink.send_batch_async(vec![Bytes::from("second"), Bytes::from("third")])
                    .await
            }
        });

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !parked.is_finished(),
            "send_batch_async must block on a full channel, not drop the batch"
        );
        assert_eq!(stats.counters().dropped_batches, 0);
        assert_eq!(
            stats.counters().sent_batches,
            1,
            "a parked send must not be counted as delivered"
        );

        // Drain the slot; the parked send must now complete and deliver.
        let landed = rx.recv().await.expect("first batch");
        assert_eq!(landed.len(), 1);

        let second = rx.recv().await.expect("second batch delivered after drain");
        assert_eq!(second.len(), 2, "no lines lost while backpressured");
        assert!(
            tokio::time::timeout(Duration::from_millis(500), parked)
                .await
                .expect("parked send completes after drain")
                .expect("task must not panic"),
            "send must report delivery once the slot frees"
        );
        assert_eq!(stats.counters().dropped_batches, 0);
        assert_eq!(stats.counters().sent_batches, 2);
    }

    /// A consumer that vanishes while an async send is parked must end the
    /// connection task rather than hang or spin. This is the disconnect
    /// tail-flush path.
    #[tokio::test]
    async fn test_async_send_reports_shutdown_when_receiver_drops() {
        let (tx, rx) = mpsc::channel(1);
        let sink = BatchSender::new(tx, 2);
        let stats = sink.stats();

        assert!(sink.send_batch_async(vec![Bytes::from("first")]).await);

        let waiter = tokio::spawn({
            let sink = sink.clone();
            async move { sink.send_batch_async(vec![Bytes::from("parked")]).await }
        });

        // Let the send park, then yank the consumer away.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(rx);

        let result = tokio::time::timeout(Duration::from_millis(500), waiter)
            .await
            .expect("parked send must not hang forever")
            .expect("task must not panic");
        assert!(!result, "a vanished consumer is a shutdown, not a delivery");
        assert_eq!(
            stats.counters().dropped_batches,
            0,
            "shutdown is not shed loss and must not be counted as such"
        );
    }

    /// The receive task must not be detached. If the output consumer goes
    /// away, `run_parsed` breaks out of its loop while the receive task is
    /// still parked in `recv_from` holding the bound socket. Without the
    /// abort-on-drop guard that task would be stranded for the life of the
    /// process.
    ///
    /// This asserts the method actually returns when the consumer vanishes —
    /// which it cannot do while holding a live `recv()` on the receive task,
    /// since the guard is what breaks that coupling.
    #[tokio::test]
    async fn test_run_parsed_returns_when_consumer_vanishes() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut config = IngestConfig::default();
        config.bind_addr = addr;
        config.batch_size = 1;
        config.batch_timeout = Duration::from_millis(5);

        let listener = UdpSyslogListener::bind(config).unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let (tx, rx) = mpsc::channel(1);
        let sink = BatchSender::new(tx, 1);
        let parser = Arc::new(UniversalParser::new());

        let server = tokio::spawn(async move {
            listener
                .run_parsed(parser, sink, BatchChannelStats::default())
                .await
        });

        // Push one batch through so the parser has something to do.
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let line = "%ASA-6-302013: Built inbound UDP connection 123 for outside:1.1.1.1/53 to inside:2.2.2.2/53\n";
        let _ = sender.send_to(line.as_bytes(), actual_addr).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Consumer disappears. `run_parsed` must notice via the closed output
        // channel, break, and tear down its receive task.
        drop(rx);

        let joined = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("run_parsed must return after the consumer vanishes")
            .expect("task must not panic");
        assert!(
            joined.is_ok(),
            "clean early exit should not report an error, got: {joined:?}"
        );
    }

    /// The pool's stats handle must expose live gauges, not zeros. This was a
    /// review finding: `counters()` filled `depth`/`capacity` from
    /// `ChannelStats::default()`, so a caller inspecting pool stats saw an
    /// empty queue even when batches were queued.
    #[tokio::test]
    async fn test_stats_handle_reports_live_gauges() {
        let (tx, mut rx) = mpsc::channel(4);
        let sink = BatchSender::new(tx, 2);
        let handle = sink.stats();

        let empty = handle.counters();
        assert_eq!(empty.depth, 0, "nothing queued yet");
        assert_eq!(
            empty.capacity, 4,
            "capacity must be recorded at construction"
        );

        sink.send_batch(vec![Bytes::from("a"), Bytes::from("b")]);
        sink.send_batch(vec![Bytes::from("c")]);

        let busy = handle.counters();
        assert_eq!(busy.depth, 2, "gauge must reflect queued batches");
        assert_eq!(busy.sent_batches, 2);
        assert_eq!(
            busy.capacity, 4,
            "capacity survives alongside the live depth"
        );

        // Draining must walk the gauge back down, or it would drift upward
        // forever and read as a permanently full queue.
        handle.record_received(1);
        assert_eq!(handle.counters().depth, 1);
        handle.record_received(1);
        assert_eq!(handle.counters().depth, 0);

        // The real receiver still holds both batches — the gauge is a
        // side-channel, not a change to the channel's own accounting.
        assert_eq!(rx.recv().await.expect("first").len(), 2);
        assert_eq!(rx.recv().await.expect("second").len(), 1);
    }

    /// `snapshot()` and `counters()` must not drift apart — they read the
    /// same shared state, so a stats line built from either agrees.
    #[tokio::test]
    async fn test_snapshot_agrees_with_stats_handle() {
        let (tx, _rx) = mpsc::channel(4);
        let sink = BatchSender::new(tx, 2);
        sink.send_batch(vec![Bytes::from("a")]);
        sink.send_batch(vec![Bytes::from("b"), Bytes::from("c")]);

        assert_eq!(sink.snapshot(), sink.stats().counters());
    }

    /// The depth gauge must not drift when a send does not land.
    ///
    /// A shed (`Full`) or a closed consumer (`Closed`) never enqueues a batch,
    /// so the pre-send increment has to be rolled back. If it were not, the
    /// gauge would ratchet upward and report a permanently full queue. The
    /// shutdown path matters most: `run_parsed` also skips `record_received`
    /// on a failed send, so a leaked increment there has nothing to cancel it.
    #[tokio::test]
    async fn test_depth_gauge_rolls_back_on_failed_send() {
        // Full-channel path: shed batches must not accumulate depth.
        let (tx, _rx) = mpsc::channel(1);
        let sink = BatchSender::new(tx, 2);
        let stats = sink.stats();

        assert!(sink.send_batch(vec![Bytes::from("a")]));
        assert_eq!(stats.counters().depth, 1);

        for _ in 0..5 {
            assert!(sink.send_batch(vec![Bytes::from("shed")]));
        }
        assert_eq!(
            stats.counters().depth,
            1,
            "shed batches must not inflate the depth gauge"
        );

        // Closed-consumer path: a failed send is not a delivery and not depth.
        let (tx2, rx2) = mpsc::channel(4);
        let sink2 = BatchSender::new(tx2, 2);
        let stats2 = sink2.stats();
        assert!(sink2.send_batch(vec![Bytes::from("first")]));
        assert_eq!(stats2.counters().depth, 1);
        drop(rx2);
        assert!(!sink2.send_batch(vec![Bytes::from("never lands")]));
        assert_eq!(
            stats2.counters().depth,
            1,
            "a closed-consumer send must not leave depth behind"
        );

        // Same for the awaited path.
        let (tx3, rx3) = mpsc::channel(4);
        let sink3 = BatchSender::new(tx3, 2);
        let stats3 = sink3.stats();
        assert!(sink3.send_batch_async(vec![Bytes::from("first")]).await);
        assert_eq!(stats3.counters().depth, 1);
        drop(rx3);
        assert!(
            !sink3
                .send_batch_async(vec![Bytes::from("never lands")])
                .await
        );
        assert_eq!(
            stats3.counters().depth,
            1,
            "a closed-consumer async send must not leave depth behind"
        );
    }

    /// Depth must be raised before the batch is visible, so a consumer that
    /// wakes immediately cannot decrement a counter that has not been
    /// incremented yet (which would underflow and wrap to a huge number).
    ///
    /// Drives a producer and a consumer against the same channel with no
    /// ordering between them, then asserts the gauge neither underflows during
    /// the race nor drifts afterwards.
    #[tokio::test]
    async fn test_depth_never_underflows_under_concurrent_drain() {
        let (tx, mut rx) = mpsc::channel(64);
        let sink = BatchSender::new(tx, 2);
        let stats = sink.stats();

        const BATCHES: usize = 200;

        let consumer_stats = stats.clone();
        let consumer = tokio::spawn(async move {
            let mut seen = 0usize;
            // Loop until the channel closes rather than a fixed count: shed
            // batches mean fewer than BATCHES ever arrive, and a fixed-count
            // loop would block forever waiting for one that was dropped.
            while rx.recv().await.is_some() {
                // Mirror the real consumer: decrement as each batch is taken.
                consumer_stats.record_received(1);
                let depth = consumer_stats.counters().depth;
                assert!(
                    depth < 1_000_000,
                    "depth underflowed: unsigned wraparound produced {depth}"
                );
                seen += 1;
            }
            seen
        });

        // Producer runs on the same runtime, releasing the final sender when
        // it finishes so the consumer's `recv` observes the close.
        for i in 0..BATCHES {
            sink.send_batch(vec![Bytes::from(format!("line-{i}"))]);
        }
        drop(sink);

        let seen = tokio::time::timeout(Duration::from_secs(5), consumer)
            .await
            .expect("consumer must drain and observe the close")
            .expect("consumer task must not panic");

        let counters = stats.counters();
        // Shed is expected under this race and is fine — what matters is that
        // exactly the delivered batches are reflected in the gauge.
        assert_eq!(counters.sent_batches, seen as u64);
        assert_eq!(
            counters.sent_batches + counters.dropped_batches,
            BATCHES as u64,
            "every produced batch is either sent or shed, never both"
        );
        assert_eq!(
            counters.depth, 0,
            "gauge must return to zero once every delivered batch is consumed"
        );
    }
}
