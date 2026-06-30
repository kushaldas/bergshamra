# Bergshamra Performance

This document tracks bergshamra's performance over time, measured with the
criterion harness in `crates/bergshamra-c14n/benches/c14n.rs`. The harness
exercises the hot paths that every XML-DSig / XML-Enc operation hits: XML
parsing, inclusive/exclusive canonicalization, and entity escaping.

## How to reproduce

```bash
# Run the harness
cargo bench -p bergshamra-c14n --bench c14n

# Save a named baseline (e.g. before a change)
cargo bench -p bergshamra-c14n --bench c14n -- --save-baseline main

# Compare the current working tree against a saved baseline
cargo bench -p bergshamra-c14n --bench c14n -- --baseline main
```

Inputs are generated deterministically in-code (no dependency on the
`test-data/` symlink), so the harness is fully reproducible:

- **saml** — namespace-heavy SAML-shaped Response with 40 nested signed
  Assertions (~29 KB). The realistic production case.
- **text_heavy** — 200 paragraphs of mostly-clean text with sparse `& < >`
  (~94 KB). Stresses `escape_text`.
- **attr_heavy** — 400 elements × 8 attributes each (~63 KB). Stresses
  attribute collection/sorting and `escape_attr`.

The `escape/*` micro-benchmarks measure `escape_text` / `escape_attr` directly
on an 8 KB string, in both **sparse** (a handful of escapable bytes) and
**dense** (an escapable byte every ~3 chars) regimes.

---

## Baseline: `main` @ `dfe78f7`

| Field | Value |
|-------|-------|
| Commit | `dfe78f79497dac3a067324a6612db6b22a8ea4d8` (main) |
| Date | 2026-06-29 |
| Toolchain | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| CPU / arch | x86_64, 12 cores |
| uppsala | `0.5.2` (crates.io) |
| criterion | `0.5.1` |
| escape impl | char-by-char (`s.chars()` loop, allocates a `String` per node) |

Median times (criterion point estimate):

| Benchmark | Median | Throughput |
|-----------|-------:|-----------:|
| `parse/saml` | 146.7 µs | ~190 MiB/s |
| `parse/text_heavy` | 137.0 µs | ~672 MiB/s |
| `parse/attr_heavy` | 437.1 µs | ~137 MiB/s |
| `c14n_inclusive/saml` | 826.9 µs | ~36 MiB/s |
| `c14n_inclusive/text_heavy` | 300.2 µs | ~307 MiB/s |
| `c14n_inclusive/attr_heavy` | 1318.4 µs | ~45 MiB/s |
| `c14n_exclusive/saml` | 661.8 µs | ~43 MiB/s |
| `c14n_exclusive/text_heavy` | 344.2 µs | ~244 MiB/s |
| `c14n_exclusive/attr_heavy` | 1170.2 µs | ~51 MiB/s |
| `escape/text_sparse` | 20.3 µs | ~340 MiB/s |
| `escape/attr_sparse` | 23.9 µs | ~319 MiB/s |
| `escape/text_dense` | 19.0 µs | ~397 MiB/s |
| `escape/attr_dense` | 19.2 µs | ~398 MiB/s |

This baseline is the contract subsequent changes are measured against:
performance must not regress, and C14N output must remain byte-identical (it is
hash input — any change breaks every signature).

---

## After: uppsala 0.6.0 + memchr escaping + `children_iter`

Commit base: branch `feat/perf-harness-uppsala-path` off `dfe78f7`. Same machine
and toolchain as the baseline above.

Changes measured here:

1. **uppsala `0.6.0`** (crates.io, up from `0.5.2`) — picks up the parser
   performance work (faster default-namespace resolution, attribute/entity
   fast paths, denser arena reservation).
2. **C14N traversal** — `doc.children()` (allocates a `Vec` per element) →
   `doc.children_iter()` (zero-allocation iterator) at all six recursion sites.
3. **Entity escaping** — per-`char` loop that allocated a `String` per node →
   `*_into` variants that append directly to the C14N output `Vec<u8>`, scanned
   adaptively: `memchr3` to bulk-skip clean runs, with a per-byte bail for dense
   regions and rare-needle inputs (see `crates/bergshamra-c14n/src/escape.rs`).
4. **Base64 transform** — `char`-level whitespace strip → byte-level strip.

### Escaping: thermal-neutral A/B (the trustworthy escape numbers)

Measured old vs new in a **single** criterion run (immune to run-to-run drift),
on an 8 KB string:

| input | old (`char` loop) | new (adaptive) | speedup |
|-------|------------------:|---------------:|--------:|
| sparse text (realistic) | 21.9 µs | 0.59 µs | **~37×** |
| dense text (adversarial) | 21.1 µs | 16.7 µs | **~1.27× (no regression)** |

The dense case matters for a security library: text rebuilt from many
`&lt;`/`&amp;` references must not become a CPU amplifier. Pure `memchr` *did*
regress there (~2× slower); the adaptive bail is what keeps dense inputs faster
than the original.

### End-to-end C14N vs the `main` baseline

| Benchmark | vs `main` |
|-----------|----------:|
| `parse/saml` | −18% |
| `parse/attr_heavy` | −8% |
| `c14n_inclusive/saml` | −30% |
| `c14n_inclusive/text_heavy` | **−85%** |
| `c14n_inclusive/attr_heavy` | −18% |
| `c14n_exclusive/saml` | −20% |
| `c14n_exclusive/text_heavy` | −75% |
| `c14n_exclusive/attr_heavy` | within noise (see below) |
| `escape/text_sparse` | **−96%** |
| `escape/attr_sparse` | −95% |
| `escape/text_dense` | −28% |
| `escape/attr_dense` | −26% |

### Measurement caveat (important)

This machine has high run-to-run variance from CPU frequency scaling: the
**same binary** measured against the same baseline produced −13%, +18%, and +8%
on `c14n_exclusive/attr_heavy` across three consecutive runs (absolute
1.10–1.38 ms). **Only deltas larger than ~±25% are meaningful here.** The large
wins above clear that bar; the lone apparent `c14n_exclusive/attr_heavy`
regression does not and is variance, not a real regression.

The authoritative no-regression evidence is therefore:

1. **Correctness — byte-identical output.** The full xmlsec suites pass
   unchanged: DSig `TOTAL OK: 447, FAILED: 0` and Enc `TOTAL OK: 701, FAILED: 0`.
   C14N output is hash input, so any changed byte would flip signature/digest
   tests to FAILED — none did.
2. **Escaping A/B** above, measured thermal-neutrally.
3. The changes are allocation reductions (`children_iter`, `*_into`) and a scan
   that is algorithmically never slower than the original per-byte — so no input
   class can regress.

### Reproduce the escape A/B

The single-run A/B scaffold (`benches/escape_ab.rs`) was removed after the
decision; to re-derive it, benchmark the old `char` loop against
`escape::escape_text` in one criterion run on sparse and dense 8 KB inputs.
