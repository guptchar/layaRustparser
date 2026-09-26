use anyhow::Result;
use bytes::Bytes;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressurePolicy {
    Block,
    Drop,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct QueueStats {
    pub pushed: u64,
    pub dropped: u64,
    pub blocked: u64,
    pub current_len: usize,
    /// Current bytes held in the queue (gauge: up on push, down on pop).
    pub queued_bytes: u64,
    /// Cumulative bytes discarded by the Drop policy.
    pub dropped_bytes: u64,
    /// Max observed `queued_bytes` since queue creation.
    pub high_water_bytes: u64,
}

pub trait LogQueue: Send + Sync {
    fn push(&self, b: Bytes) -> Result<()>;
    fn pop_batch(&self, max_batch_size: usize) -> Vec<Bytes>;
    fn stats(&self) -> QueueStats;
}

struct MemoryQueueInner {
    queue: Mutex<VecDeque<Bytes>>,
    not_empty: Condvar,
    not_full: Condvar,
    capacity: usize,
    policy: BackpressurePolicy,
    pushed: AtomicU64,
    dropped: AtomicU64,
    blocked: AtomicU64,
    // Byte accounting stays beside the count counters so push/pop can
    // update both under the same queue lock with relaxed atomics.
    queued_bytes: AtomicU64,
    dropped_bytes: AtomicU64,
    high_water_bytes: AtomicU64,
}

pub struct MemoryQueue {
    inner: Arc<MemoryQueueInner>,
}

impl MemoryQueue {
    pub fn new(capacity: usize, policy: BackpressurePolicy) -> Self {
        Self {
            inner: Arc::new(MemoryQueueInner {
                queue: Mutex::new(VecDeque::with_capacity(capacity)),
                not_empty: Condvar::new(),
                not_full: Condvar::new(),
                capacity,
                policy,
                pushed: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
                blocked: AtomicU64::new(0),
                queued_bytes: AtomicU64::new(0),
                dropped_bytes: AtomicU64::new(0),
                high_water_bytes: AtomicU64::new(0),
            }),
        }
    }
}

impl LogQueue for MemoryQueue {
    fn push(&self, b: Bytes) -> Result<()> {
        let inner = &self.inner;
        let mut queue = inner.queue.lock().unwrap();

        match inner.policy {
            BackpressurePolicy::Block => {
                while queue.len() >= inner.capacity {
                    inner.blocked.fetch_add(1, Ordering::Relaxed);
                    queue = inner.not_full.wait(queue).unwrap();
                }
                // Byte gauge moves here (not in the consumer) so a
                // shutdown tail-drop can't leak the counter upward.
                let len = b.len() as u64;
                queue.push_back(b);
                inner.pushed.fetch_add(1, Ordering::Relaxed);
                let current = inner.queued_bytes.fetch_add(len, Ordering::Relaxed) + len;
                inner.high_water_bytes.fetch_max(current, Ordering::Relaxed);
                inner.not_empty.notify_one();
                Ok(())
            }
            BackpressurePolicy::Drop => {
                if queue.len() >= inner.capacity {
                    inner.dropped.fetch_add(1, Ordering::Relaxed);
                    inner
                        .dropped_bytes
                        .fetch_add(b.len() as u64, Ordering::Relaxed);
                    return Ok(());
                }
                let len = b.len() as u64;
                queue.push_back(b);
                inner.pushed.fetch_add(1, Ordering::Relaxed);
                let current = inner.queued_bytes.fetch_add(len, Ordering::Relaxed) + len;
                inner.high_water_bytes.fetch_max(current, Ordering::Relaxed);
                inner.not_empty.notify_one();
                Ok(())
            }
        }
    }

    fn pop_batch(&self, max_batch_size: usize) -> Vec<Bytes> {
        let inner = &self.inner;
        let mut queue = inner.queue.lock().unwrap();

        if queue.is_empty() {
            return Vec::new();
        }

        let batch_size = std::cmp::min(max_batch_size, queue.len());
        let mut batch = Vec::with_capacity(batch_size);
        let mut bytes_popped: u64 = 0;
        for _ in 0..batch_size {
            if let Some(item) = queue.pop_front() {
                // `len()` borrows the buffered bytes — no copy on this path.
                bytes_popped += item.len() as u64;
                batch.push(item);
            }
        }

        if bytes_popped > 0 {
            inner
                .queued_bytes
                .fetch_sub(bytes_popped, Ordering::Relaxed);
            inner.not_full.notify_all();
        }

        batch
    }

    fn stats(&self) -> QueueStats {
        let inner = &self.inner;
        let queue = inner.queue.lock().unwrap();
        QueueStats {
            pushed: inner.pushed.load(Ordering::Relaxed),
            dropped: inner.dropped.load(Ordering::Relaxed),
            blocked: inner.blocked.load(Ordering::Relaxed),
            current_len: queue.len(),
            queued_bytes: inner.queued_bytes.load(Ordering::Relaxed),
            dropped_bytes: inner.dropped_bytes.load(Ordering::Relaxed),
            high_water_bytes: inner.high_water_bytes.load(Ordering::Relaxed),
        }
    }
}

#[cfg(feature = "broker")]
pub mod broker {
    use super::{BackpressurePolicy, LogQueue, QueueStats};
    use anyhow::Result;
    use bytes::Bytes;
    use std::sync::atomic::{AtomicU64, Ordering};

    pub struct BrokerQueue {
        pushed: AtomicU64,
        dropped: AtomicU64,
        blocked: AtomicU64,
        queued_bytes: AtomicU64,
        dropped_bytes: AtomicU64,
        high_water_bytes: AtomicU64,
    }

    impl BrokerQueue {
        pub fn new(_capacity: usize, _policy: BackpressurePolicy) -> Self {
            Self {
                pushed: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
                blocked: AtomicU64::new(0),
                queued_bytes: AtomicU64::new(0),
                dropped_bytes: AtomicU64::new(0),
                high_water_bytes: AtomicU64::new(0),
            }
        }
    }

    impl LogQueue for BrokerQueue {
        fn push(&self, _b: Bytes) -> Result<()> {
            self.pushed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn pop_batch(&self, _max_batch_size: usize) -> Vec<Bytes> {
            Vec::new()
        }

        fn stats(&self) -> QueueStats {
            QueueStats {
                pushed: self.pushed.load(Ordering::Relaxed),
                dropped: self.dropped.load(Ordering::Relaxed),
                blocked: self.blocked.load(Ordering::Relaxed),
                current_len: 0,
                queued_bytes: self.queued_bytes.load(Ordering::Relaxed),
                dropped_bytes: self.dropped_bytes.load(Ordering::Relaxed),
                high_water_bytes: self.high_water_bytes.load(Ordering::Relaxed),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BackpressurePolicy, LogQueue, MemoryQueue};
    use bytes::Bytes;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_memory_queue_basic_push_pop() {
        let queue = MemoryQueue::new(10, BackpressurePolicy::Block);
        queue.push(Bytes::from("test1")).unwrap();
        queue.push(Bytes::from("test2")).unwrap();

        // Both payloads are live in the queue before the pop.
        let mid = queue.stats();
        assert_eq!(mid.queued_bytes, 10);
        assert_eq!(mid.high_water_bytes, 10);

        let batch = queue.pop_batch(5);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0], Bytes::from("test1"));
        assert_eq!(batch[1], Bytes::from("test2"));

        let stats = queue.stats();
        assert_eq!(stats.pushed, 2);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.blocked, 0);
        assert_eq!(stats.current_len, 0);
        assert_eq!(stats.queued_bytes, 0);
        assert_eq!(stats.dropped_bytes, 0);
        assert_eq!(stats.high_water_bytes, 10);
    }

    #[test]
    fn test_memory_queue_pop_batch_limit() {
        let queue = MemoryQueue::new(10, BackpressurePolicy::Block);
        for i in 0..10 {
            queue.push(Bytes::from(format!("item{}", i))).unwrap();
        }

        let batch = queue.pop_batch(3);
        assert_eq!(batch.len(), 3);
        let stats = queue.stats();
        assert_eq!(stats.current_len, 7);
        // "item0".."item9" are 5 bytes each: 50 queued, 15 popped, 35 left.
        assert_eq!(stats.queued_bytes, 35);
        assert_eq!(stats.high_water_bytes, 50);
    }

    #[test]
    fn test_memory_queue_drop_policy() {
        let queue = MemoryQueue::new(3, BackpressurePolicy::Drop);
        queue.push(Bytes::from("1")).unwrap();
        queue.push(Bytes::from("2")).unwrap();
        queue.push(Bytes::from("3")).unwrap();
        queue.push(Bytes::from("4")).unwrap();
        queue.push(Bytes::from("5")).unwrap();

        let stats = queue.stats();
        assert_eq!(stats.pushed, 3);
        assert_eq!(stats.dropped, 2);
        assert_eq!(stats.current_len, 3);
        // Single-byte payloads: 3 queued, 2 dropped, high-water 3.
        assert_eq!(stats.queued_bytes, 3);
        assert_eq!(stats.dropped_bytes, 2);
        assert_eq!(stats.high_water_bytes, 3);

        let batch = queue.pop_batch(10);
        assert_eq!(batch.len(), 3);
    }

    #[test]
    fn test_memory_queue_block_policy_blocks_producer() {
        let queue = Arc::new(MemoryQueue::new(2, BackpressurePolicy::Block));
        queue.push(Bytes::from("1")).unwrap();
        queue.push(Bytes::from("2")).unwrap();

        let queue_clone = queue.clone();
        let handle = thread::spawn(move || {
            queue_clone.push(Bytes::from("3")).unwrap();
        });

        thread::sleep(Duration::from_millis(50));
        let stats = queue.stats();
        assert!(stats.blocked > 0);

        let _ = queue.pop_batch(1);
        handle.join().unwrap();

        let stats = queue.stats();
        assert_eq!(stats.pushed, 3);
        // Popped "1" (1 byte), blocked "3" lands: "2" + "3" live, peak 2.
        assert_eq!(stats.queued_bytes, 2);
        assert_eq!(stats.high_water_bytes, 2);
    }

    #[test]
    fn test_memory_queue_concurrent_producers_consumers() {
        let queue = Arc::new(MemoryQueue::new(100, BackpressurePolicy::Block));
        let num_producers = 4;
        let items_per_producer = 25;

        let mut handles = Vec::new();
        for p in 0..num_producers {
            let q = queue.clone();
            handles.push(thread::spawn(move || {
                for i in 0..items_per_producer {
                    q.push(Bytes::from(format!("p{}i{}", p, i))).unwrap();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let mut total_popped = 0;
        while total_popped < num_producers * items_per_producer {
            let batch = queue.pop_batch(10);
            total_popped += batch.len();
        }

        let stats = queue.stats();
        assert_eq!(stats.pushed, 100);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.current_len, 0);
        // Full drain returns the byte gauge to zero; the high-water mark
        // stays as the only record of peak pressure.
        assert_eq!(stats.queued_bytes, 0);
        assert_eq!(stats.dropped_bytes, 0);
        assert!(stats.high_water_bytes > 0);
    }

    #[test]
    fn test_memory_queue_empty_pop_returns_empty() {
        let queue = MemoryQueue::new(10, BackpressurePolicy::Block);

        let batch = queue.pop_batch(1);
        assert!(batch.is_empty());

        queue.push(Bytes::from("data")).unwrap();
        let batch = queue.pop_batch(1);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0], Bytes::from("data"));
    }

    #[test]
    fn test_memory_queue_stats_accuracy() {
        let queue = MemoryQueue::new(5, BackpressurePolicy::Block);
        queue.push(Bytes::from("a")).unwrap();
        queue.push(Bytes::from("b")).unwrap();

        let _ = queue.pop_batch(1);

        queue.push(Bytes::from("c")).unwrap();

        let stats = queue.stats();
        assert_eq!(stats.pushed, 3);
        assert_eq!(stats.current_len, 2);
        // 1 + 1 pushed, 1 popped, 1 pushed: 2 bytes live, peak 2.
        assert_eq!(stats.queued_bytes, 2);
        assert_eq!(stats.high_water_bytes, 2);
    }

    #[test]
    fn test_memory_queue_dropped_bytes_consistency() {
        // Dropped count and dropped bytes must agree: 3 kept, 2 shed.
        let queue = MemoryQueue::new(3, BackpressurePolicy::Drop);
        queue.push(Bytes::from("aa")).unwrap();
        queue.push(Bytes::from("bb")).unwrap();
        queue.push(Bytes::from("cc")).unwrap();
        queue.push(Bytes::from("dd")).unwrap();
        queue.push(Bytes::from("eeee")).unwrap();

        let stats = queue.stats();
        assert_eq!(stats.dropped, 2);
        assert_eq!(stats.dropped_bytes, 6);
        assert_eq!(stats.queued_bytes, 6);
        // Shed bytes never touch the live gauge.
        assert_eq!(stats.high_water_bytes, 6);
    }

    #[test]
    fn test_memory_queue_full_drain_returns_bytes_to_zero() {
        let queue = MemoryQueue::new(16, BackpressurePolicy::Block);
        let mut expected: u64 = 0;
        for i in 0..8 {
            let payload = format!("log-line-{}", i);
            expected += payload.len() as u64;
            queue.push(Bytes::from(payload)).unwrap();
        }
        assert_eq!(queue.stats().queued_bytes, expected);

        let mut drained: u64 = 0;
        loop {
            let batch = queue.pop_batch(3);
            if batch.is_empty() {
                break;
            }
            drained += batch.iter().map(|b| b.len() as u64).sum::<u64>();
        }
        assert_eq!(drained, expected);
        let stats = queue.stats();
        assert_eq!(stats.current_len, 0);
        assert_eq!(stats.queued_bytes, 0);
        assert_eq!(stats.high_water_bytes, expected);
    }

    #[test]
    fn test_memory_queue_high_water_mark_survives_drain() {
        let queue = MemoryQueue::new(16, BackpressurePolicy::Block);
        // Fill to a peak, drain halfway, push again below the old peak:
        // the mark must pin at the historic maximum, not the live gauge.
        for _ in 0..4 {
            queue.push(Bytes::from("12345")).unwrap(); // 20 bytes peak
        }
        assert_eq!(queue.stats().high_water_bytes, 20);

        let _ = queue.pop_batch(2); // 10 live
        assert_eq!(queue.stats().queued_bytes, 10);

        queue.push(Bytes::from("abc")).unwrap(); // 13 live, peak still 20
        let stats = queue.stats();
        assert_eq!(stats.queued_bytes, 13);
        assert_eq!(stats.high_water_bytes, 20);

        // A new peak pushes the mark up with the gauge.
        queue.push(Bytes::from("1234567890")).unwrap(); // 23 live
        let stats = queue.stats();
        assert_eq!(stats.high_water_bytes, 23);
    }
}
