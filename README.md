# Beyond What Code LLMs Say — Probing Internal Representations for Rust Vulnerability Detection

M.S. thesis project · Gurman Singh Marahar · Texas A&M University–San Antonio · advisor Prof. Yang
Progress brief, September 2026 (updated Sep 16 with the cross-model replication). All 7–9B experiments run on a free Colab T4; the 24B model on a GCP L4.

---

## Background

HALURust ([arXiv:2503.10793](https://arxiv.org/abs/2503.10793)) detects Rust vulnerabilities with a two-step trick: ask an LLM to write a report about the code, then classify the report. Its own ablation shows why the trick matters — classifying the code directly with the same fine-tuned model reaches only about 50% F1, while classifying the report reaches about 75%. The paper never asks why the detour works.

This project started as an extension of HALURust's dataset. When that alone was judged not novel enough, we turned the ablation into a question about mechanism. If the model can only detect vulnerabilities after it has talked about the code, either it does not know until it reasons out loud, or it already knows and simply cannot say so when asked directly. These two explanations predict different things about the model's internal state, so they can be tested.

## The idea

Take a frozen code model and show it two versions of the same Rust function: the vulnerable one and its fix. Then measure two things on exactly the same pairs.

- **The mouth.** Ask the model directly whether the code is vulnerable, and score its answer.
- **The brain.** Read the model's internal activations at one layer and train a small linear classifier (a *probe*) to tell the two versions apart.

Both are scored the same way — how often the vulnerable twin is ranked above its fix (*pairwise accuracy*), so a coin flip is 0.50 and perfect is 1.00. If the mouth is at chance while the brain is well above it, the model knows more than it says, and HALURust's detour is a way of recovering knowledge that is already there.

## What we did

### 1. Cleaning the ground truth (August)

Before running anything, every record of the 251-row vulnerable/fixed dataset was audited against the RustSec advisory database and each repository's git history. Of 245 unique CVEs, 221 reference commits checked out cleanly. Eleven pointed at the wrong commit, four SHAs did not exist, two changed no Rust code, two were mislabelled, and twelve advisories were never patched upstream. Every experiment below uses only the **228 clean pairs**, and each pair carries its CWE, crate, advisory date and commit date, which is what makes the time-based test possible.
→ `docs/02_reference_commit_audit.md`, `data/Halurust_SHA_audit.xlsx`, `data/halurust_metadata.csv`

### 2. Is there anything to read? (Phase 1, Aug 28)

Hidden states of Qwen2.5-Coder-7B were extracted for every function and a probe trained at every layer, with cross-validation folds grouped by CVE so that no twin of a test pair is ever seen in training. The best layer (24 of 28) ranked the vulnerable twin above its fix 0.82 of the time, and the same held on CVEs from 2024 onward. We also found something we had to take seriously: because fixes usually add code, the trivial rule *"the shorter twin is vulnerable"* scores 0.81 by itself. From then on every probe result had to be compared against this length shortcut.
→ `notebooks/phase1_probing_sc.ipynb`

### 3. Does the mouth match the brain? (Phase 1.5, Sep 1)

The probe was re-run with bootstrap confidence intervals and, on the same pairs, the Instruct version of the model was asked directly in three ways: a plain yes/no question, a yes/no question framed as a security audit, and a forced choice where both twins are shown and the model must say which is vulnerable. Answers were scored from the model's own answer-token probabilities. **The mouth was at chance on every prompt: 0.50, 0.54, 0.50. The brain read 0.80 (95% CI 0.75–0.85)**, and 0.83 when trained only on pre-2024 CVEs and tested on 56 later ones. What this run could not resolve was whether the probe was doing anything beyond the length shortcut: on the CVE pairs the probe and the length rule make nearly the same mistakes (McNemar p = 0.89).
→ `notebooks/phase15_ladder.ipynb`

### 4. Security, or just the shape of a patch? (Phase 1.5b, Sep 2)

To answer that, we built a control set. From the same repositories we mined 1,133 ordinary before/after function pairs from commits that were not security fixes — no advisory, no security vocabulary in the commit message, not adjacent to a known fix — and selected 226 whose length pattern matches the CVE pairs almost exactly (79% vs 80% "after is longer"; the length rule scores 0.80 on both sets). Then we applied the CVE-trained probe to them. If the probe had learned "shorter means vulnerable", it would score about 0.80 here too. **It scored 0.61.** Two further checks agreed: removing length from the activations made the probe better, not worse (0.80 → 0.83), and padding the vulnerable twin with comments until it became the longer one did not change its choice. The control set also included 42 non-security bug-fix commits, where the probe scored 0.67.
→ `notebooks/phase15b_controls_v2.ipynb`, `data/control_pairs.zip`, `code/control_mining/`

### 5. Does it hold in other model families? (Phase 2, Sep 13–16)

Prof. Yang asked whether the result is specific to Qwen. The identical pipeline — probe, mouth, temporal split, non-security control — was rerun on four more families: **CodeLlama-7B** (code model, training data ends mid-2023, so most of the 2024+ CVEs post-date it), **Gemma-2-9B** (general-purpose; the family HALURust's own classifier was built on), **Llama-3.1-8B** (general-purpose) and **Mistral-Small-24B** (three times the size; run on a GCP L4). Same 228 pairs, same 226 control pairs, same prompts and clip lengths.

| | Qwen2.5-Coder-7B | CodeLlama-7B | Gemma-2-9B | Llama-3.1-8B | Mistral-Small-24B |
|---|---|---|---|---|---|
| Mouth — zero-shot / expert / A-B forced choice | 0.50 / 0.54 / 0.50 | 0.38 / 0.42 / 0.50 | 0.52 / 0.47 / 0.52 | 0.55 / 0.52 / 0.50 | 0.58 / 0.58 / 0.50 |
| **Brain — linear probe (CVE pairs)** | **0.796** [0.746, 0.846] | **0.770** [0.715, 0.825] | **0.768** [0.711, 0.820] | **0.761** [0.706, 0.814] | **0.787** [0.735, 0.838] |
| Brain — trained pre-2024, tested 2024+ (n = 56) | 0.830 | 0.804 | 0.857 | 0.821 | 0.839 |
| Brain — length regressed out | 0.833 | 0.776 | 0.781 | 0.772 | 0.789 |
| **Control — same probe on non-security patches** | **0.606** | **0.628** | **0.591** | **0.597** | **0.644** |
| Control — non-security bug fixes (n = 42) | 0.667 | 0.702 | 0.679 | 0.643 | 0.702 |
| Length rule (CVE pairs / control pairs) | 0.805 / 0.801 | 0.805 / 0.801 | 0.805 / 0.801 | 0.805 / 0.801 | 0.805 / 0.801 |

Five families, one picture: the mouth is at a coin flip everywhere (CodeLlama's yes/no answers are even slightly *inverted*; the 24B model's are the best, at 0.58, and still nowhere near its own probe), the brain reads 0.76–0.80, the signal survives on CVEs disclosed after the models' training data, and it drops to 0.59–0.64 on ordinary patches with the same length pattern. Tripling model size (7B → 24B) changes almost nothing.
→ `notebooks/xmodel_codellama7b.ipynb`, `notebooks/xmodel_gemma2_9b.ipynb`, `notebooks/xmodel_llama31_8b.ipynb`, `notebooks/xmodel_mistral24b.ipynb`, `results/xmodel/`, `code/gen_multi_model_notebooks.py`

## The numbers

| Measurement | Value | 95% CI / n |
|---|---|---|
| Mouth — zero-shot yes/no · expert yes/no · A/B forced choice | 0.50 · 0.54 · 0.50 | n = 228 |
| Length rule — shorter twin is vulnerable | 0.805 | eq-len subset 0.68 |
| **Brain — linear probe, layer 24 of 28** | **0.796** | [0.746, 0.846] · 228 |
| Brain — trained on pre-2024 CVEs, tested on 2024+ | 0.830 | [0.723, 0.920] · 56 |
| Brain — after regressing length out of the activations | 0.833 | [0.785, 0.879] · 228 |
| **Control — same probe on ordinary (non-security) patches** | **0.606** | [0.542, 0.668] · 226 |
| Control — length rule on those same ordinary patches | 0.801 | 226 |
| Control — same probe on non-security bug-fix commits | 0.667 | [0.524, 0.798] · 42 |
| Placebo — vulnerable twin padded to be the longer one | 0.871 → 0.906 | 159 pairs, 26 flips |

Frozen Qwen2.5-Coder-7B (base, 4-bit), mean-pooled hidden states, standardised logistic regression, CVE-grouped 5-fold CV. Mouth: Qwen2.5-Coder-7B-Instruct, first-answer-token probabilities. Same 228 audited pairs throughout. Raw numbers: `results/phase15b_results.json`.

## What we found

**The model knows more than it says.** Asked in any of three ways, including being shown both twins and forced to choose, it is at a coin flip; read internally, the same code separates at 0.80 — and the same holds in CodeLlama, Gemma-2, Llama-3.1 and Mistral-24B (0.76–0.79). That is a direct explanation of HALURust's ablation: the knowledge is present in the activations and lost in decoding, and the report-generation step was compensating for that loss.

**It is not memorisation.** Trained on CVEs disclosed before 2024 and tested on those disclosed later — code the model is very unlikely to have seen with its label — the probe still reads 0.83, while the mouth stays at 0.50. CodeLlama, whose training data ends in 2023, reads 0.80 on those same pairs.

**It is mostly about security, not about what a patch looks like.** On ordinary patches with the identical length pattern, the length rule still scores 0.80 but the probe falls to 0.61. Removing length helps the probe, and making the vulnerable version longer does not fool it. The result is graded — ordinary edits 0.61, bug fixes 0.67, security fixes 0.80 — and the same ordering appears in CodeLlama, Gemma-2, Llama-3.1 and Mistral-24B, so we read the 0.19 gap between ordinary patches and security fixes as the security-specific part of the signal, and the 0.11 the probe keeps on ordinary patches as a generic "older version of the code" sense that any twin-based evaluation should subtract.

**A methodological point.** The pairwise twin metric used across this literature does not cancel length; it hands any method an 0.80 free ride. We propose reporting the overall pairwise score, the equal-length subset, single-sample AUC, and a matched non-security control together, with confidence intervals. No prior work on probing code models for bugs runs a say-versus-know comparison, an audited real-CVE corpus, a time-based split, a non-security control, or Rust (see `REFERENCES.md`).

## Where the evidence is weaker

The single-sample AUC is modest, around 0.60: the probe is much better at saying which of two versions is worse than at judging one function in isolation. The equal-length subset has only 36 pairs. One of the four control tests (a cross-dataset AUC) turned out to be confounded — the CVE files and the control files are distinguishable as datasets because HALURust's extraction leaves artefacts our parser does not — so it is excluded; the three within-pair tests are immune to that. Control commits were filtered by commit-message vocabulary, so a few silent security fixes may remain among them; that would push the control score up, which works against our claim rather than for it.

## What comes next

Two directions are open. **Generality:** CodeLlama, Gemma-2, Llama 3.1 and Mistral-24B are done; next are DeepSeek-Coder, StarCoder2 and a Qwen size sweep, with frontier models such as Gemini and GPT providing mouth-only baselines since their internals cannot be read (`docs/08_multi_model_plan.md`). **Training:** with the GCP credit, fine-tune on the CVE pairs and re-probe, to see whether training moves the brain, the mouth, or both — and check on the control set that a trained model learns security rather than patch shape.

---

## Repository map

```
README.md                      this brief
REFERENCES.md                  every paper, database and method cited, with links
docs/
  progress_brief.html          the same brief as a formatted page
  01_probing_study_design_and_results.md   full design + Phase 1 / 1.5 / 1.5b / 2 results log (rev. 8)
  02_reference_commit_audit.md             the 251-row commit audit (method, verdicts, wrong rows)
  03_probing_explainer.md                  plain-language explanation of every term (pre-Phase-1)
  04_extraction_methodology_and_audit.md   how pairs were extracted; leakage measurements; threats to validity
  05_stage2_prompting_decisions.md         notes on the report-generation route that was set aside
  06_extraction_spec_and_progress.md       batch-by-batch extraction record (rows 200–232)
  07_halurust_v2_roadmap.md                the original critique of HALURust's pipeline (Aug 5)
  08_multi_model_plan.md                   next step: which models and why
notebooks/
  phase1_probing_sc.ipynb        Phase 1 (self-contained; data embedded)
  phase15_ladder.ipynb           Phase 1.5 say-vs-know ladder + statistics
  phase15b_controls_v2.ipynb     Phase 1.5b controls (4 tests)
  xmodel_codellama7b.ipynb       Phase 2: same pipeline on CodeLlama-7B (+Instruct)
  xmodel_gemma2_9b.ipynb         Phase 2: same pipeline on Gemma-2-9B (+it)
  xmodel_llama31_8b.ipynb        Phase 2: same pipeline on Llama-3.1-8B (+Instruct)
  xmodel_mistral24b.ipynb        Phase 2: same pipeline on Mistral-Small-24B (GCP L4)
data/
  halurust_metadata.csv          245 CVEs: cwe, crate, repo, rustsec_id, dates, never_patched, audit verdict
  Halurust_SHA_audit.xlsx        the dataset sheet + 10 audit columns
  cve_pairs.zip                  Positive/ (vulnerable) and Negative/ (fixed) Rust function pairs, 251 each
  control_pairs.zip              Before/ and After/ of 268 non-security pairs
  control_meta.csv               per control pair: repo, commit, date, category, files, lengths
code/
  audit/                         crates.io → repo resolution, git fetch by SHA, advisory matching, verdicts
  control_mining/                clone.py, rustitems.py (Rust item parser), mine.py, sample.py, gen15b.py
  pilot_0.5B/                    CPU pilot with Qwen2.5-Coder-0.5B
  gen_phase15_notebook.py        generator for the Phase 1.5 notebook
  gen_multi_model_notebooks.py   generator for the Phase 2 cross-model notebooks (one per model)
results/
  phase15b_results.json          all Phase 1.5b numbers incl. per-layer transfer curve
  xmodel/results_<model>.json    Phase 2 numbers per model (probe, temporal, control, residualised, mouth)
  pilot_results_0.5B.csv, *.jpg  pilot table and screenshots of the Phase 1 / 1.5 result cells
```

Notebooks are self-contained (data embedded as base64) and run top-to-bottom on a Colab T4 in about an hour each. Note: run the cells individually or in two halves — Colab's "Run all" restarted the runtime after the `pip install -U` step in our runs.
