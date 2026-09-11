# HaluRust v2 — Pipeline Critique and Redesign Roadmap (Aug 5 2026)

> Historical note. This is the first planning document of the project, written when the dataset had
> 195 records and the plan was a critique-and-extension of HALURust's report pipeline. The four
> reviewer attacks in §2 (prompt leakage, twin leakage in Algorithm 1, contamination, 1:1 balance)
> shaped everything that followed; the paper framing in §3 was later replaced by the probing study
> (`01_probing_study_design_and_results.md`) after Prof. Yang asked for a more novel contribution.

Prepared for Gurman · RA work under Prof. Yang · August 2026

---

## 1. Where the dataset stood (Aug 5)

| Metric | Paper | Dataset then |
|---|---|---|
| CVE records | 81 | **195** (now 251 / 245 unique) |
| Distinct CWEs | 44 | **83** (after normalization) |
| Distinct programs/crates | 54 | **142** (after case-folding) |
| Commit SHAs present | — | **195 / 195** |
| Missing version field | — | 10 rows |

**Temporal spread** — the single most valuable asset:

```
2015:1  2017:2  2018:4  2019:11  2020:23  2021:42
2022:32 2023:21 2024:38 2025:19  2026:2
```

136 CVEs from ≤2023 and 59 from 2024 onward. GPT-4o's training cutoff is ~Oct 2023; Llama 3's is
~Dec 2023. So one can train on pre-cutoff data and test on post-cutoff data. **The original paper
could not do this** — all 81 of its CVEs predate every model it used.

### Data-quality fixes identified

- **CWE zero-padding is inconsistent** — `CWE-020` and `CWE-20` both appear. Normalize to `CWE-` + int.
- **Crate names differ by case** — `Wasmtime`/`wasmtime`, `Tokio`/`tokio`. Corrupts project-level splits.
- **10 rows have no version.** Backfill from the advisory.
- **50 of 83 CWEs have exactly one sample.** Full multi-class CWE prediction is not viable; the
  4-category grouping from the paper's Table 1 is.

### RustSec, not just NVD

RustSec's advisory-db is the Rust ecosystem's own advisory database — machine-readable TOML, with
structured `patched`/`unaffected` version ranges, CVE cross-references, and CVSS. A rigorously
curated 300-CVE Rust vulnerability dataset with extracted function pairs is a publishable artifact
on its own (MSR data/tool track).

---

## 2. Four things a reviewer will attack in the original pipeline

### 2.1 Label leakage through the prompt — the big one

From HALURust §4.2: for vulnerable samples the report-generation context is the CVE description; for
non-vulnerable samples it is not; at test time neither class gets the description. During
**training**, positive samples had the real CVE description injected. So the fine-tuned classifier
may simply be learning *"was a CVE description in the prompt when this report was written?"* — a
proxy for the label. At **test** time the positive class has a different generating distribution
than in train: a textbook train/test shift, and a plausible explanation for the 77% ceiling and the
swings across the 5 selection rounds.

The ablation is cheap: regenerate reports for vulnerable samples *without* the CVE description,
retrain, measure the delta. Either outcome is publishable.

### 2.2 The split protocol probably leaks twins

Each CVE yields a vulnerable sample and its fixed twin, differing by a handful of tokens.
Algorithm 1 ("Diverse Sample Selection") greedily picks the sample *least* similar to the last one
added; nothing keeps a CVE's two samples on the same side of the split, and maximizing
dissimilarity tends to *separate* them.

- The greedy anti-similarity chain front-loads outliers into training and leaves the redundant core
  in test.
- **The pseudocode has a bug.** The loop condition is `while |S'| < p × |S|`, but `S` shrinks each
  iteration. With `p = 0.8`, this terminates at roughly 44% selected, not 80%.

**Fix:** group-aware splitting by CVE; also report project-level and temporal splits.
*(Adopted: every probe result uses CVE-grouped CV; a random split was measured at 0.092 AUC — see `04_…` §6.)*

### 2.3 No contamination control

All 81 original CVEs are public and predate every model's cutoff. "Varying performance across
prompts suggests it's not just memorization" is not an argument. The post-2024 CVEs allow the real
test. *(Adopted: temporal split, 0.83 on 56 post-2024 pairs.)*

### 2.4 The 1:1 class balance is fiction

Every CVE contributes one positive and one negative, so evaluation runs at 50% prevalence. Real
codebases are perhaps 0.1–1% vulnerable functions. At 1% prevalence, 73% precision / 76% recall at
balance degrades to roughly **2.7% precision** — about 36 false alarms per true finding. Also,
"the fixed function is non-vulnerable" is an assumption: several crates appear repeatedly
(`wasmtime` 15×), meaning some "non-vulnerable" samples were later patched again.

**Fix:** hard negatives from the same file/crate never touched by any advisory; PR-AUC and MCC
alongside F1. *(Partly adopted: the Phase 1.5b control set is exactly "untouched-by-advisory"
before/after pairs from the same repositories.)*

---

## 3. Paper framings considered (superseded)

**A. "Is it hallucination, or is it leakage?"** — re-examination under contamination and leakage
controls. **B. Training-free detection via self-consistency** — K sampled reports; agreement as the
signal (SelfCheckGPT-style). **C. Detection is not localization** — report span ∩ patch hunk.
All three remain possible follow-ups; the probing study replaced them as the main contribution.

---

## 4. Redesigned pipeline (as proposed)

```
Stage 0 CURATION     RustSec advisory-db + NVD → normalized CVE table
Stage 1 EXTRACTION   git @ fix_commit^ → enclosing fn(s) of each hunk = POSITIVE;
                     same fn(s) @ fix_commit = NEGATIVE; untouched fns = HARD NEGATIVE
Stage 2 REPORTS      identical prompt for both classes; no CVE description; K samples; hash-cache
Stage 3 DETECTION    consistency → groundedness → TF-IDF+LogReg → small encoder → QLoRA 7B
Stage 4 EVALUATION   CVE-grouped | project-held-out | temporal; PR-AUC, MCC, F1;
                     contamination-stratified; localization; bootstrap CIs + McNemar
```

Notes that survived into the probing study: Qwen2.5-Coder-7B in 4-bit instead of Gemma-7B;
run the cheap baseline ladder first and stop early if it explains the result; cache everything;
report cost.

## 5. Research questions pitched then

1. Does HaluRust's performance survive removal of CVE-description leakage?
2. How much is attributable to memorization of public CVEs?
3. Does a training-free self-consistency signal match fine-tuned classification?
4. Do these detectors localize vulnerabilities, or only classify them?
5. How does performance degrade at realistic prevalence?

RQ2 (memorization) and the split/leakage discipline carried directly into the probing study.

---

*Sources: HALURust (arXiv:2503.10793) · RustSec advisory-db · SelfCheckGPT (arXiv:2303.08896) ·
audit of `Gurman_Halurust_Combined_Dataset.xlsx`.*
