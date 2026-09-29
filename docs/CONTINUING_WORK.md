# Continuing Work — Research Notes

Working notes for in-flight issues: what the code does today, what was decided,
and why. Each entry is written *before* the build so the reasoning survives the
diff.

---

## #9 — Onboarder: CEF + JSON synthesizers, real LRU eviction

**Branch:** `feat/9-cef-json-synthesizers` → transplanted to
`feat/9-cef-json-synthesizers-v2` (old branch was 14 commits behind master and
carried an already-merged docs commit; work reused, not duplicated).

### State of the code on master before this change

`Onboarder::synthesize_regex` dispatched on three shapes only (flow-arrow, KV,
positional). CEF and JSON fell through to the positional tokenizer, which
shreds them: CEF loses its `spt=`/`dpt=` short keys entirely (the KV branch only
knows `sport=`/`srcport=`/`dport=`), and a JSON line is shredded on whitespace.

Registry eviction: **already LRU on master** (`onboarder.rs:1314-1325`,
`min_by(last_use, key)` over a `BTreeMap`, capacity 256, introduced in 92ae9ee).
The `parsers.clear()` the issue describes is gone. The "real LRU" acceptance
criterion is therefore satisfied by existing code; this change adds the
*behavioural test* that pins it (hot parser survives 120 churn registrations),
not a second eviction implementation.

### Decisions

**Dispatch order — CEF and JSON are checked BEFORE the flow-arrow branch.** A CEF
extension block can legally contain `->`; an EVE `signature` string can
legally contain `->`. Checking `->` first routes both into
`synthesize_flow_regex` and builds a pattern around the wrong anchor. `CEF:` and
a leading `{` are the more specific signals, so they win.

**CEF synthesizer** anchors on `^.*?CEF:\d+\|` with seven `[^|]*` header fields.
Header captures are `cef_`-prefixed — deliberately unknown to
`parse_with_regex`, so they land in `unmapped` as provenance instead of
colliding with endpoint captures. Every extension key clause is `\b`-prefixed
so `src=` cannot match inside `srcintf=`/`srcip=`. `src_ip`/`dst_ip` are
mandatory: a pattern without endpoint captures can never pass the sandbox
validator, so the error names the sample instead of failing opaquely later.

The action group reuses the `action` capture name, so `parse_with_regex` needs
no runtime change.

**JSON synthesizer — no hand-rolled JSON grammar.** The issue hint is right that
regex-parsing JSON by hand is the fragile option. Instead: parse samples with
`serde_json` (already a direct dep — nothing new added), flatten each document
to scalar key paths, and emit one regex anchored at `^\s*\{` whose clauses are
`regex::escape`d *literal keys* joined by `.*?`. Quoting, nesting and key order
are handled by matching literals, not by parsing structure.

Two subtleties the shape of the code forces:

- *Clause order.* `serde_json::Map` is alphabetical without `preserve_order`,
  so document order is read off the raw sample text by `str::find` on the
  quoted key — the same trick the KV branch uses.
- *Presence across samples.* A path in every sample becomes a mandatory clause;
  a path in only some (`alert.action`, absent from EVE `flow`/`dns` records)
  becomes `(?:...)?`. Otherwise a mixed-type training set — which is exactly
  what you get from an EVE corpus — could never validate.
- *Value class.* Observed type decides: strings quoted, numbers bare (EVE emits
  `"src_port": 56529`), mixed accepts either.
- *Nested scoping.* A nested path (`alert.action`) scopes its leaf inside the
  parent object with `[^}]*?`, not `.*?`, so the join cannot spill past the
  parent's closing brace.

**`schema_version` field.** `#[serde(default)]` on the new field is
load-bearing, not laziness: `from_yaml` rejects missing fields, so without the
default every `data/parsers/*` file published before this change would stop
loading. New files stamp `PARSER_SCHEMA_VERSION` (1); legacy files report 0.
Surfaced in `GET /parsers` as `schema_version`, `None` for native extractors
and for rows that never deserialized — the sentinel is more honest than a
fabricated `1`.

### Two things this branch does NOT change

- `crates/ulpf-cli/src/serve/handlers.rs` had a text conflict on cherry-pick:
  master carries merged #61/#62 (slug grouping, `source_path`, unreadable-vs-
  malformed reporting). Master was kept and only the `schema_version` field was
  ported in. No behaviour was reverted.
- The old branch's docs commit (hygiene restructure) is dropped — it was
  squash-merged as #72 already.

### Verification

`cargo clippy --workspace --all-targets -D warnings` clean, `cargo fmt --check`
clean, `cargo test --workspace` green. Two timing tests
(`test_classification_sub_microsecond_benchmark`, `test_drain_microsecond_performance`)
fail intermittently on this box under load — both pass in isolation; this is the
known-flake class #58 tracks.
