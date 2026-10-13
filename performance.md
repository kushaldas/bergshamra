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

---

## Memory analysis: bergshamra 0.7.0 + uppsala 0.9.0

Date: 2026-07-05.

Context: this pass focuses on peak resident memory during XML-DSig and XML-Enc
operations. The Uppsala 0.9 work brought three lessons that apply directly
here:

1. Use the pull parser/event contract when a full DOM is not required.
2. Treat legal output amplification as a resource-management problem and expose
   caller-configurable caps.
3. Keep hot scanners/serializers covered by differential tests, because
   performance rewrites need correctness oracles.

### Measurements

Measured with the release binary and `/usr/bin/time -v` on this machine. Peak
RSS includes process startup and loaded crypto code, so the tiny-file rows show
the floor. The large fixture is a generated enveloped RSA-SHA256 signature over
a 9.9 MB XML document with one same-document `#root` reference and an
enveloped-signature + exclusive-C14N transform chain.

| Operation | Input | Elapsed | Peak RSS | Notes |
|---|---:|---:|---:|---|
| verify RSA KeyValue | 1.2 KB | <0.01 s | 4.8 MB | `xmldsig11` RSA-SHA256 |
| verify SAML X509 | 8.2 KB | <0.01 s | 5.1 MB | embedded X509, `--insecure` |
| decrypt AES-KW/AES-CBC | 1.3 KB | <0.01 s | 4.4 MB | `01-phaos-xmlenc-3` |
| sign RSA template | 0.6 KB | <0.01 s | 4.6 MB | Aleksey RSA-SHA256 |
| sign generated fixture | 1.98 MB | 0.40 s | 50.9 MB | about 26x input size |
| verify generated fixture | 1.98 MB | 0.14 s | 49.9 MB | about 25x input size |
| sign generated fixture | 9.90 MB | 1.27 s | 236.5 MB | about 24x input size |
| verify generated fixture | 9.90 MB | 0.85 s | 233.4 MB | about 24x input size |

The important result is linear but high memory growth. For common DSig
same-document references, the process currently keeps several document-sized
buffers/structures live at once: original XML text, parsed DOM arenas, full
node-set membership, canonicalized output, and often replacement/output XML.

### Allocation drivers

1. **Whole-document NodeSets are materialized as `HashSet<usize>`.**
   `NodeSet::all`, `all_without_comments`, `tree_without_comments`, and
   `tree_with_comments` insert every visible node into a hash table
   (`crates/bergshamra-xml/src/nodeset.rs`). The enum already has
   `Tree`, `TreeWithoutComments`, `TreeInvert`, and `Invert` shapes, but the
   constructors used on hot paths produce `Normal` sets. This is the largest
   avoidable metadata cost for large DOMs.

2. **TransformData owns the whole XML string.**
   `TransformData::Xml { xml_text: String, node_set }` means URI resolution and
   transform execution clone the full input for same-document references
   (`crates/bergshamra-transforms/src/pipeline.rs` and
   `crates/bergshamra-dsig/src/verify.rs`). On large signed documents this adds
   another input-sized allocation per active reference pipeline.

3. **Verification still uses the generic transform pipeline for the common
   enveloped-signature + C14N path.**
   Signing now has a direct same-document fast path that canonicalizes the
   resolved node set without the generic transform pipeline. Verification still
   resolves `xml.to_owned()`, builds `NodeSet`, applies transforms, then calls
   `to_binary()`. Porting the signing fast path to verification should reduce
   both allocations and reparses for the most common SAML/WS-Security shape.

4. **Canonicalization buffers the entire canonical XML before hashing.**
   `inclusive::canonicalize` and `exclusive::canonicalize` return `Vec<u8>`.
   For digest verification the canonical bytes are immediately hashed, so the
   full vector is transient but peak-RSS-visible. A sink-based API
   (`canonicalize_into` or `canonicalize_to_digest`) would let DSig hash while
   rendering.

5. **C14N does per-element namespace and attribute allocation.**
   Inclusive and exclusive C14N repeatedly build `BTreeMap`, `HashSet`, `Vec`,
   and owned `String`s for in-scope namespaces, visibly-used prefixes,
   attributes, and rendered names. This is correct but allocation-heavy on
   documents with many shallow elements.

6. **XML-Enc replacement paths duplicate output-sized buffers.**
   Encryption/decryption use node byte ranges and construct replacement output
   buffers. That is reasonable for a string-returning API, but CLI and library
   callers handling large opaque payloads would benefit from byte/output caps
   and eventually streaming output.

### Prioritized work

1. **Port the DSig signing fast path to verification.**
   Detect same-document URI + transforms limited to enveloped-signature and C14N,
   canonicalize directly on the already-parsed `Document`, and skip
   `TransformData::Xml { xml_text: xml.to_owned() }`. This should help the
   dominant SAML-style verification path immediately.

2. **Change `NodeSet` storage away from `HashSet<usize>` for common shapes.**
   Use the existing `NodeSetType` idea structurally: store root IDs and set type
   for whole-document/subtree cases, and reserve dense bitsets or sorted vectors
   for arbitrary XPath-filter results. A `Vec<u64>` bitset would be much smaller
   than a hash table while preserving O(1) membership for C14N traversal.

3. **Add sink-based canonicalization.**
   Keep the existing `Vec<u8>` API for compatibility, but implement it on top of
   a lower-level writer/sink API. DSig digest paths should feed a hash sink
   directly. Signing still needs canonicalized `SignedInfo` bytes for the
   signature operation, but reference digesting does not need the full buffer.

4. **Borrow or share XML text in the transform pipeline.**
   Replace owned `String` in `TransformData::Xml` with a borrowed lifetime or
   shared `Arc<str>` style wrapper. Longer-term, pass a parsed document context
   through XML-aware transforms so Base64, XPath, enveloped-signature, and C14N
   do not reparse the same string.

5. **Add resource caps mirroring Uppsala's pattern.**
   Add defaults and builder/CLI overrides for maximum input bytes, maximum
   canonicalized reference bytes, maximum transform output bytes, maximum
   decrypted plaintext bytes, and maximum `verify_all` signatures/references.
   Defaults should pass the xmlsec suites and fail closed on hostile
   amplification.

6. **Create a memory benchmark harness.**
   Add reproducible generated fixtures for parse, sign, verify, encrypt, and
   decrypt. Record peak RSS in CI/manual runs. The existing
   Criterion harness covers time, not memory, and RSS scaling is currently the
   more actionable signal.

### Expected impact

The likely first win is verification fast-pathing plus borrowed transform XML:
it removes at least one full XML clone and avoids the generic transform path for
the dominant case. The larger structural win is compact/lazy `NodeSet`
storage. On the 9.9 MB generated fixture, reducing whole-document/subtree
`HashSet` materialization and hashing C14N into a sink should bring peak RSS
substantially closer to "input + DOM + output" instead of the observed ~24x
input multiplier.

---

## P0/P1 measurement infrastructure + build profile

Date: 2026-10-07. Toolchain: `rustc 1.99.0 (b940084d7 2026-09-28)`, 8 cores.

The work was sequenced as numbered phases: P0 measurement
harnesses and saved baselines, P1 build profile, P2 C14N allocation hygiene,
P3 NodeSet and hashing representations, P4 duplicate-work audit (parse once
per operation), P5 concurrency and large-input paths, P6 startup latency.
P0 through P3 are complete and described below, P6 was measured and needs
no work, and P4 and P5 remain open.

P0 and P1:

1. **P0 harnesses** (all committed):
   - `crates/bergshamra-dsig/benches/dsig_e2e.rs` — end-to-end sign/verify over
     the SAML-shaped fixture family, RSA-2048 and HMAC-SHA256, 40 and 400
     assertions. HMAC variants isolate the XML pipeline from the asymmetric
     primitive.
   - `scripts/gen_fixture.py` + `scripts/membench.sh` — deterministic 30 KB /
     1 MB / 10 MB fixtures, `/usr/bin/time -v` peak-RSS and elapsed for CLI
     sign and verify (`just bench-memory`).
   - `scripts/hyperfine.sh` (`just bench-cli`) — warm-path verify timing and
     startup; two-binary A/B mode.
   - Baselines saved: `cargo bench … -- --save-baseline plan-p0` for both
     benches (c14n and dsig_e2e) before the P1 changes landed.

2. **P1 changes**:
   - `[profile.release]` = fat LTO, `codegen-units = 1`, `strip = true`
     (no `panic = "abort"`: library workspace, consumers embed these crates).
   - `[profile.dev] debug = "line-tables-only"`; new `[profile.profiling]`.
   - `[patch.crates-io] kryptering = { path = "../kryptering" }` — the local
     0.6.1 working tree, for crypto-path iteration. All 189 unit tests pass
     with the patch; C14N byte-identity is covered by the xmlsec suites.

### Initial P0 baseline (no LTO tuning)

| Metric | Value |
|---|---:|
| CLI startup (`--version`) | 3.2 ms |
| CLI verify small (30 KB SAML) | 7.6 ms |
| CLI verify large (10.7 MB) | 581 ms |
| peak RSS sign/large | 97.7 MB (1.12 s) |
| peak RSS verify/large | 73.7 MB (0.67 s) |
| sign/enveloped_rsa_40 | 3.92 ms |
| verify/enveloped_rsa_40 | 1.20 ms |
| sign/enveloped_hmac_400 | 8.32 ms |
| verify/enveloped_hmac_400 | 8.37 ms |

(criterion medians; c14n numbers for this baseline are the `plan-p0` saved
baseline, not reproduced here.)

### After P1 (fat LTO + codegen-units=1 + local kryptering 0.6.1)

| Metric | P0 | P1 | Delta |
|---|---:|---:|---:|
| CLI verify large | 581 ms | 513 ms | −12% |
| c14n_inclusive/saml | 866 µs | 680 µs | **−19%** |
| c14n_exclusive/saml | 307 µs | 255 µs | −16% |
| c14n_exclusive/attr_heavy | 903 µs | 580 µs | **−39%** |
| c14n_inclusive/attr_heavy | 1.64 ms | 1.55 ms | −11% |
| verify/enveloped_hmac_400 | 8.37 ms | 7.00 ms | −16% |
| verify/enveloped_hmac_40 | 922 µs | 778 µs | −13% |
| sign/enveloped_rsa_40 | 3.92 ms | 3.96 ms | noise |
| CLI verify small / startup | 7.6 / 3.2 ms | 8.1 / 3.8 ms | noise |

Small apparent regressions (`parse/attr_heavy` +5.7%, `escape/text_sparse`
+12.9% on a 1.4 µs benchmark, `sign/enveloped_hmac_400` +8.5%) are within the
documented ±25% machine-variance band; the structural C14N/verify wins clear
it comfortably.

### Reproduce

```sh
cargo bench -p bergshamra-c14n --bench c14n -- --baseline plan-p0
cargo bench -p bergshamra-dsig --bench dsig_e2e -- --baseline plan-p0
just bench-memory
just bench-cli
```

---

## P2 experiments: applying the uv learnings (C14N allocation hygiene)

Date: 2026-10-07. Five experiments, each implemented, proven byte-identical via
the xmlsec suites (DSig 447 OK / 0 FAILED, Enc 700 OK / 0 FAILED — the lone Enc
skip is kryptering 0.6.1 deliberately rejecting weak DH-1024), and measured
against criterion baselines. All 200+ unit tests pass; zero clippy warnings.

| # | Learning (file) | Change | Result |
|---|---|---|---|
| E1 | 01-allocation-hygiene | Stream element names from the arena (no per-element `format!`); zero-alloc `write_to` for ns decls + attrs in inclusive C14N (exclusive already had it); drop defensive `text`/PI clones | inclusive −50…−65% (first measurement); exclusive −13…−17% |
| E2 | 08-algorithmic-wins | Replace the O(depth)-per-element `collect_inscope_namespaces` ancestor walk with an incrementally maintained in-scope map + undo log (the push/pop pattern exclusive.rs already used) | inclusive additional −12…−60% |
| E3 | 05-string-interning (rustc-hash) | `NodeSet` storage `HashSet<usize>` → `FxHashSet` (`NodeIdSet` alias), incl. verify.rs id sets | (measured in stack, below) |
| E4 | 06-io #4 buffer reuse | Pre-size the C14N output sink to `doc.input_text().len()` in `canonicalize_doc_to` | (measured in stack, below) |
| E5 | 01 #6 borrow, 05 sharing | `Attr` → lifetime-generic with `Cow<'a, str>` fields borrowed from the uppsala arena (was 4 owned `String`s per attribute; ~12.8k allocs per attr_heavy canonicalize) | (measured in stack, below) |

### Measurement caveat

This machine's thermal variance degraded during the session: identical code
measured parse/saml at 295 µs and 559 µs in consecutive runs (±90% on an
*untouched* benchmark). Only deltas far outside that band are attributable;
single-run small deltas are not. The inclusive-C14N wins clear the bar in three
independent comparisons; exclusive/text_heavy wobbled ±15–30% both directions
and is reported as noise. Thermal-neutral stash A/B was used for the ambiguous
cases (it confirmed inclusive/text −23%, i.e. *faster*).

### Cumulative c14n results (vs `e0` baseline = post-P1 tree)

| Benchmark | e0 | after E1–E5 | Delta |
|---|---:|---:|---:|
| c14n_inclusive/saml | 807 µs | 210 µs | **−74%** |
| c14n_inclusive/attr_heavy | 1409 µs | 449 µs | **−68%** |
| c14n_inclusive/text_heavy | 75 µs | 58 µs | −22% |
| c14n_exclusive/saml | 232 µs | 176 µs | −24% |
| c14n_exclusive/attr_heavy | 490 µs | 442 µs | −11% |
| c14n_exclusive/text_heavy | 76 µs | ~85 µs | noise |

### End-to-end dsig_e2e (vs `plan-p0` = post-P1 tree)

| Benchmark | plan-p0 | after E1–E5 | Delta |
|---|---:|---:|---:|
| verify/enveloped_hmac_40 | 922 µs | 680 µs | **−28%** |
| verify/enveloped_hmac_400 | 8.37 ms | 6.52 ms | **−22%** |
| sign/enveloped_hmac_40 | 966 µs | 901 µs | −12% |
| sign/enveloped_rsa_40 | 3.92 ms | 3.59 ms | −8% |
| verify/enveloped_rsa_40 | 1.20 ms | 1.07 ms | −3% (noise band) |
| sign/enveloped_hmac_400 | 8.32 ms | 8.04 ms | noise band |

### Design notes

- E2's incremental in-scope map preserves the exact undeclaration semantics of
  the old walk (`xmlns=""` stays an empty-string entry; prefixed
  undeclarations remove the prefix) and the ns-filter `child_ns` scoping, so
  byte-identity is structural, not test-luck.
- E5 keeps `NsDecl` owned for now (1–3 per element vs 8+ attributes; the Cow
  clone from uppsala is a pointer copy in the common Borrowed case).
- The `unwrap()` discipline was tightened while here: all
  `doc.element(id).unwrap()` panics in serialization paths became
  `element_of()` → `Error::Canonicalization`, and guarded `Option::unwrap()`s
  were restructured — a security library must not abort on an inconsistent
  arena.

### Not applied (with reasons)

- 03 rkyv / 07 rayon: N/A (rkyv has no repeated-deserialize workload;
  verify_all parallelism is the open P5 item and needs DOM aliasing analysis
  first).
- 04 OnceMap: no concurrent same-work dedup hotspot in a single-operation CLI.
- 10 caching/startup: startup measured 3.2–3.8 ms — no work needed.
- 12 fork upstream: uppsala is not the bottleneck anymore (parse benches are
  drift-bound and untouched by all of the above).

---

## Python binding layer: optimized crates + GIL release (pybergshamra)

Date: 2026-10-07. The same optimizations now measured through
`../pybergshamra` (PyO3 extension, lesson 13):

- pybergshamra builds against this workspace via `[patch.crates-io]` plus its
  own fat-LTO release profile.
- All hot entry points now release the GIL (`py.detach`): verify, verify_all,
  sign, sign_enveloped, canonicalize, canonicalize_subtree, encrypt/decrypt.

Python-layer medians (`pybergshamra/benchmarks/pybench.py`, HMAC fixtures):

| Benchmark | published 0.9.2 | optimized + GIL release |
|---|---:|---:|
| canonicalize/large (10.7 MB) | 461 ms | ~210 ms (**−55%**) |
| verify/hmac_large | 332 ms | ~260 ms (−20%) |
| sign_enveloped/hmac_small | 2.96 ms | 1.72 ms (−42%) |
| verify_small × 4 threads (wall) | 7.56 ms | 3.0–3.3 ms (**−57%**) |
| thread scaling | 0.41× | 0.81–1.29× |

Full tables: `pybergshamra/docs/performance/20261007-optimized-crates-gil-release.md`.

---

## uppsala 0.12.0 bump (ported P0–P2 tree)

Date: 2026-10-09. The P0–P2 work above was ported onto `main` and the
`uppsala` requirement raised from 0.10.1 to the published 0.12.0, which
brings direct DOM construction (ADR 0019), fused descendant XPath walks
(ADR 0020), pre-sized serialization buffers, and dependency-free fast hashing
for node-ID maps. Bergshamra's C14N and NodeSet code is identical in both
columns, so the parse and end-to-end deltas isolate the uppsala upgrade; the
C14N rows act as the noise-floor control.

A/B method: both trees built with the same toolchain and release profile
(fat LTO), harnesses run back to back on the same machine, two runs each for
c14n, best-of-two medians compared. The perf_work column was
built against the local kryptering 0.6.1 working tree; this tree uses
kryptering 0.6.0 from crates.io, so the RSA rows carry a crypto-path confound.

| Benchmark | uppsala 0.10.1 | uppsala 0.12.0 | Delta |
|---|---:|---:|---:|
| parse/saml | 259 µs | 180 µs | **−31%** |
| parse/text_heavy | 248 µs | 207 µs | **−16%** |
| parse/attr_heavy | 680 µs | 640 µs | −6% |
| c14n_inclusive/saml | 184 µs | 179 µs | noise (control) |
| c14n_inclusive/attr_heavy | 470 µs | 449 µs | noise (control) |
| c14n_exclusive/saml | 185 µs | 178 µs | noise (control) |
| c14n_exclusive/attr_heavy | 471 µs | 495 µs | noise (control) |
| verify/enveloped_hmac_40 | 669 µs | 524 µs | **−22%** |
| verify/enveloped_hmac_400 | 6.43 ms | 5.09 ms | **−21%** |
| sign/enveloped_hmac_40 | 776 µs | 655 µs | **−16%** |
| sign/enveloped_hmac_400 | 7.40 ms | 6.54 ms | −12% |
| verify/enveloped_rsa_40 | 1.01 ms | 0.92 ms | −9% |
| sign/enveloped_rsa_40 | 3.72 ms | 3.99 ms | +7% (kryptering confound + RSA noise) |

The end-to-end HMAC wins exceed the parse wins alone because every verify
and sign reparses for same-document references (the parse-once audit, open
item P4 above, is still pending) — each saved parse is paid several times per
operation. Correctness gates unchanged: xmlsec DSig 447 OK / 0 FAILED /
3 SKIPPED, Enc 700 OK / 0 FAILED / 1 SKIPPED (the deliberate DH-1024
rejection), 181 unit tests, zero clippy warnings on both the default and the
`--no-default-features` CI feature sets.
