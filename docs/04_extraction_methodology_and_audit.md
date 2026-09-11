# HaluRust — Sample Extraction Methodology, Data-Quality Audit, and Leakage Measurements

Prepared for Gurman · RA work under Prof. Yang · August 2026
Companion to `07_halurust_v2_roadmap.md`

**Scope of this document.** It records how the vulnerable/safe Rust sample pairs in the expanded
HaluRust dataset were produced, what was found wrong with the source metadata along the way, and
what the finished corpus measures on leakage baselines. Sections 4–6 are written to be usable
more or less directly in a Threats to Validity section.

**Corpus covered:** 60 extracted pairs / 120 samples, spanning dataset rows 200–232 plus 27
records added to reach 250 total.

---

## 1. Extraction protocol

Per CVE, two files with **identical filenames**: `CVE-<YEAR>-<ID>_CWE-<CWE-ID>.rs`. The first is
the vulnerable version (parent commit), the second the safe version (fix commit); the two are
distinguished by presentation order, not by filename. No suffixes, no added comments, raw
repository code only.

**Steps.**

1. Resolve `Program / Crate` → `owner/repo`. `crates.io/api/v1/crates/<name>` gives the
   `repository` field. When it is `null`, the RustSec advisory TOML at
   `raw.githubusercontent.com/rustsec/advisory-db/main/crates/<crate>/<RUSTSEC-ID>.md` carries a
   `url` field pointing at the upstream repo or issue.
2. Identify the **real fix commit** (see §2 — this is where the supplied metadata failed).
3. Fetch the changed file(s) verbatim at both the parent and the fix commit.
4. Diff locally. Identify every **non-test** function whose body a hunk touches.
5. Extract those functions by brace matching, plus any new helper functions the fix introduces
   (these appear only in the safe file; the asymmetry is real and reflects the actual patch).
6. Verify every output line is a verbatim substring of its source file before the pair is accepted.

**Scope conventions.** Hunks in `tests/`, `benches/`, `examples/`, docs and changelogs are
excluded. Where a fix spans several files, extraction targets the file containing the semantic
fix; call-site refactors elsewhere are noted, not extracted. Where a fix sprawls across many
functions, the single function carrying the vulnerability semantics is taken. Where the fix is
only a line or two (a trait bound, a type change), the enclosing type and the methods that make
the unsoundness *reachable* are pulled in as well — see §5.1.

**Environment notes** (relevant to anyone reproducing this):

- `raw.githubusercontent.com` serves byte-exact file contents at any commit SHA.
- GitLab-hosted crates need
  `gitlab.com/api/v4/projects/<ns%2Fname>/repository/files/<url-encoded-path>/raw?ref=<sha>`.
  At least one record (`bam`) is GitLab-only; a GitHub-only extractor drops it silently.
- Fetching a `.patch` URL and parsing it is **not** reliable for large diffs — retrieval
  summarised rather than returned verbatim text. Fetching whole files at both commits and
  diffing locally is the safe method.
- Quick repo+SHA validity check:
  `curl -o /dev/null -w '%{http_code}' https://raw.githubusercontent.com/<owner>/<repo>/<sha>/Cargo.toml`

---

## 2. Data-quality audit of the source metadata

### 2.1 The `Reference Commit` column is largely wrong (sampled audit — superseded by `02_reference_commit_audit.md`)

Every supplied SHA was checked against the fix commit named in the corresponding RustSec advisory,
and confirmed by reading the commit subject.

**15 of the 19 SHAs verified were not the security fix.** What they actually were:

| Crate | Supplied SHA is actually |
|---|---|
| qwutils | a version-bump commit ("qwutils 0.3.1") |
| postscript | "Fix the number encoding in Type 2" — unrelated |
| calamine | "fix(XLSX): support replacing row/column ranges" — unrelated |
| marc | merge PR #17, "Fix Indicator::second()" — unrelated |
| cdr | merge PR #14, unrelated |
| generator | "fix rust 1.91.0-nightly warnings" — a 2025 commit |
| lever | merge PR #23 "fix-warnings" — a `compare_and_swap` deprecation |
| eventio, sys-info, kekbit, basic_dsp_matrix | lint / clippy / test cleanups |
| arc-swap, multiqueue2, buttplug, ruspiro-singleton | unrelated merges or benchmark fixes |
| lazy-init | "Implement Debug for Lazy\<T\>" |
| hashconsing, slock, socket2, concread, abi_stable, rusb, xcb, av-data | unrelated to the advisory |

The pattern: the `repo_search` provenance selects commits that *touch the crate*, not the commit
that *fixes the CVE*. Rows whose provenance was `commit_diff` fared better (v9 was correct).

**Why this matters beyond bookkeeping.** Extracting from the wrong commit yields a pair that looks
structurally valid — two versions of a real function, a real diff — but the delta is a lint fix or
a version bump. The pair is then labelled vulnerable/safe and carries no vulnerability signal at
all. It is silent corruption: nothing downstream will flag it.

**Remedy.** Most RustSec advisories name their fix commit in prose ("This flaw was fixed in commit
`8026286` by…"). Since every row already carries a RUSTSEC ID, the whole column can be re-derived
by script and diffed against what `repo_search` produced. **This should be done for the pre-existing
rows as well, not only the ones added here** — the same method produced them. *(Done on Aug 26 —
see `02_reference_commit_audit.md`; the full audit found the column in much better shape than this
sample suggested: 221/251 verified.)*

### 2.2 Never-patched advisories

Eleven advisories in the candidate pool have `patched = []` — the crate was never fixed. These can
**never** yield a vulnerable/safe pair, regardless of which commit is found:

fil-ocl, buffoon, cgc, noise_search, scottqueue, rcu_cell, signal-simple, async-coap,
atomic-option, multiqueue, toolshed.

Filter on `patched != []` before counting a candidate list toward a target.

### 2.3 Duplicates

The sheet contained **228 CVE rows but only 222 unique CVEs** before this work. Six CVE-IDs were
already duplicated: CVE-2021-32715, CVE-2021-32629, CVE-2021-31919, CVE-2021-38186,
CVE-2021-28033, CVE-2021-27378. A further five candidates were rejected during extraction because
they were already present (va-ts, async-h1, image, branca, smallvec). Note also that
CVE-2020-35919 legitimately covers two crates (socket2 and net2) — a CVE-ID is not a primary key.

### 2.4 NVD CWE labels are inconsistent for this bug class

The *identical* defect — a missing `Send`/`Sync` bound on an `unsafe impl` — is labelled by NVD as:

- **CWE-362** (Race Condition) — abox, libsbc, ticketed_lock, conqueue, beef, disrustor, reffers
- **CWE-662** (Improper Synchronization) — gfwx, eventio
- **CWE-667** (Improper Locking) — va-ts
- **CWE-77** (Command Injection) — syncpool, lever — *plainly wrong; no command execution exists in these crates*
- **NVD-CWE-noinfo** — max7301, generator, late-static, magnetic

Same code pattern, same one-token fix, five different labels. Any CWE-category model trained on
NVD labels inherits this noise as an accuracy ceiling unrelated to the model. Either normalise the
labels with a documented mapping, or use the 4-category grouping from the paper's Table 1, which
absorbs most of the disagreement.

---

## 3. Verification protocol

Every delivered file passed a mechanical check: each non-blank line must appear verbatim in the
source file fetched from the repository at that commit. Nothing was reconstructed from a diff,
paraphrased, reformatted, or reindented. Where a name occurs many times in one file — 17
occurrences of `read_bytes_default_le` in byte_struct's macro body — the correct occurrence was
selected by matching a marker string taken from the diff, not by index.

Two failure modes this caught in practice: an extractor grabbing a trait *declaration*
(`fn foo(&self);`) instead of the impl with a body, and a brace matcher over-running a
semicolon-terminated item (`struct Lexer;`) into the following function.

---

## 4. Structural shapes that break naive extraction

Six shapes appeared that a name-based, function-level extractor mishandles:

1. **Derive-level vulnerabilities** — nalgebra CVE-2021-38190. The flaw was in
   `#[cfg_attr(feature = "serde-serialize", derive(Serialize, Deserialize))]`; no vulnerable
   function body exists.
2. **Deletion fixes** — id-map, telemetry, byte_struct. The fix *removes* code, so the safe sample
   is a fraction of the vulnerable one (id-map: 48 L → 6 L before re-cutting).
3. **Formatting churn inside the fix commit** — reorder. rustfmt ran alongside the fix, so ~148 of
   the changed lines are cosmetic and the vulnerable sample is visibly less tidy than the safe one.
4. **Macro-generated code** — byte_struct. The vulnerable code lives inside a `macro_rules!` body.
5. **Proc-macro authoring code** — derive-com-impl. The vulnerable code is inside a `quote!` block:
   Rust that generates Rust. The sample is not the code that runs.
6. **Non-Rust fixes** — comrak CVE-2021-27671. The entire fix is one line of PEG grammar in
   `src/lexer.pest`; `html.rs` and `parser/autolink.rs` are byte-identical across the fix. There is
   no Rust pair. Substituting the (identical) Rust wrapper would produce a zero-delta labelled pair —
   worse than dropping the record.

---

## 5. Sample-adequacy finding

### 5.1 Declaration-only samples

Eight pairs initially consisted of a type declaration plus one or two `unsafe impl Send/Sync`
lines, with **no function body, no control flow, and no memory operation** — the entire fix being a
single trait-bound token. Example (abox, before): 11 lines, of which 3 were the struct and 2 the
impls.

This is fatal for HaluRust specifically. The pipeline hands code to an LLM and asks for a
vulnerability report, then classifies on the hallucination signature. Given a bare declaration
there is nothing to hallucinate *about* — the report is short and generic for both classes alike,
and the confabulated mechanism, location and data flow the method depends on have no surface to
attach to. The actual data race also lives in *caller* code absent from the sample, so the sample
is necessary-but-not-sufficient evidence even in principle.

**Resolution.** All eight were re-cut to include the methods that make the unsoundness reachable —
`AtomicBox::take`/`replace_with` (an `Arc::from_raw` after a compare-and-swap), ticketed_lock's
`Deref` through `Arc<UnsafeCell<T>>`, conqueue's `push`/`pop`, syncpool's `checkout`/`release`,
nalgebra's `as_slice`/`as_vec_mut`. Every added method is **unchanged between the two commits**, so
the label boundary is untouched. Sizes went from 9–23 L to 35–102 L. Declaration-only pairs in the
final corpus: **0**.

**Generalisable check:** before accepting a pair, assert that both sides contain executable code.

---

## 6. Leakage measurements on the finished corpus

60 pairs / 120 samples / ~50,700 tokens.

| Measurement | Value |
|---|---|
| Best length-only threshold classifier | **55.0%** |
| Lexical TF-IDF + LogReg, leave-one-CVE-out CV | **58.3%** |
| Best single-keyword rule (`unsafe` present) | 61.8% |
| Same lexical model, **random 5-fold** split | **21.7%** |
| Stratified dummy baseline | ~48–50% |
| Mean / median twin similarity (character-level) | 77.7% / 87.5% |
| Safe longer / shorter / equal | 22 / 14 / 24 |

**Three things follow.**

**(a) Report the length and keyword baselines as explicit floors.** A classifier seeing only line
count reaches 55.0%; one keying on the presence of `unsafe` reaches 61.8%. Neither uses security
information. Any headline accuracy should be read against these, not against 50%.

**(b) Random splits are catastrophic, and this is measurable, not theoretical.** Under a random
5-fold split the same model scores **21.7% — far worse than chance.** The vulnerable and safe sides
are 87.5% identical at the median, so when a twin lands in training and its partner in test, the
model's nearest neighbour is a near-identical text with the *opposite* label and it predicts
backwards. This is a concrete, reproducible demonstration of the split-protocol concern raised in
§2.2 of the roadmap. **CVE-grouped splitting is mandatory**, and the 21.7% figure is worth
reporting as evidence rather than merely asserting that grouping matters.

**(c) The corpus is too small to fine-tune on directly.** 120 samples and ~50,700 tokens is roughly
one long document. Even the full 250-record dataset yields ~500 samples. These pairs are *stage-2
pipeline input* — material for report generation — not training data for a code classifier. Under a
correct grouped split, a shallow lexical model reaches only 58.3% against a ~50% baseline, which
says the transferable lexical signal is close to nil.

**CWE distribution.** 21 distinct CWEs across 60 pairs, **13 appearing exactly once**
(CWE-362: 16, CWE-908: 9, CWE-415: 6, CWE-787: 5, CWE-416: 3, CWE-79: 3, long tail thereafter).
Multi-class CWE prediction is not viable at this scale; the 4-category grouping is.

---

## 7. Suggested Threats to Validity points

1. Fix-commit provenance in the source metadata was unreliable; commits were re-derived from
   RustSec advisory prose and confirmed by commit subject. (All rows have since been audited —
   `02_reference_commit_audit.md`.)
2. Sample extraction is function-level; methods lifted from an `impl` block are not accompanied by
   their enclosing wrapper and will not compile standalone. This matches the original paper's
   presentation (its Listing 1) but should be stated.
3. Vulnerable and safe samples are ~87% identical at the median, so evaluation results depend
   heavily on split protocol; CVE-grouped splits were used, and a random split is shown to invert
   the classifier.
4. Sample length correlates with the label (safe longer in 22 of 60 pairs, shorter in 14); a
   length-only baseline reaches 55.0% on this subset (0.805 pairwise on the full audited corpus).
5. CWE labels derive from NVD, which labels the same defect class inconsistently and in at least
   two cases incorrectly; four labels in this corpus were assigned from advisory text where NVD
   returned `NVD-CWE-noinfo`.
6. One record (comrak CVE-2021-27671) has no Rust-level fix and is represented by a composite
   sample; a second (bam) is GitLab-hosted; a third (derive-com-impl) is proc-macro authoring code
   rather than executing code.

---

*Sources: RustSec advisory-db · NVD CVE API · crates.io API · upstream repositories at the commits
cited in the dataset's `Reference Commit` column.*
