# Probing Study — Design + Phase 1, 1.5, 1.5b, 2 & 4 RESULTS (rev. 12, Sep 29 2026)

Working title: **"Beyond What Code LLMs Say: Probing Internal Representations for Rust Vulnerability Detection."**

## ★★★★★ PHASE 4 RESULT — does fine-tuning close the say–know gap? (Colab Enterprise L4, Sep 29 2026)

Prof. Yang asked for one model to be fine-tuned. Notebook `notebooks/phase4_finetune_qwen25coder7b.ipynb`
(self-contained, data embedded), raw numbers `results/finetune/results_Qwen2.5-Coder-7B-Instruct-QLoRA.json`.
The frozen-model result for Qwen2.5-Coder-7B is mouth 0.50 / 0.54 / 0.50 vs probe 0.796. Here the **same Instruct
checkpoint is QLoRA-tuned to answer the yes/no question** (4-bit nf4 base, LoRA r = 16, α = 32, dropout 0.05 on every
attention and MLP projection, 40.4 M trainable parameters = 0.53 %; lr 1e-4 with warm-up + linear decay, 2 epochs,
gradient accumulation 8, code clipped to 2 400 tokens, loss only on the answer tokens `Yes`/`No` + end-of-turn) in
the **same CVE-grouped 5-fold CV** as every earlier phase: each fold's adapter sees ~366 samples and is scored only on
its ~92 held-out samples (46 pairs), the five held-out sets are pooled (n = 228 pairs) and bootstrapped. Per fold we
re-measure the three things the earlier phases measured on frozen models: **mouth** (P1 yes/no first-token
probability, pairwise; A/B forced choice with both orderings), **brain** (a linear probe on the *tuned* model's
mean-pooled hidden states, layer chosen by inner CV on the training fold) and the **length-matched non-security
control** (mouth and probe of every fold-model on the 226 non-fix pairs and 42 bug-fix pairs, averaged over the five
fold-models). The same notebook first scores the *untuned* Instruct model on the identical folds, including — for the
first time — a probe on the Instruct checkpoint's own hidden states. ~3.5 h of L4 time (37 min baseline + 5 × ~35 min).

| | Untuned Qwen2.5-Coder-7B-Instruct | QLoRA-tuned (5 held-out folds, pooled) |
|---|---|---|
| **Mouth** yes/no, pairwise (AUC) | 0.518 (0.505) | **0.553** [0.489, 0.618] (0.560) |
| Mouth, A/B forced choice | 0.531 [0.469, 0.596] | **0.526** [0.465, 0.592] |
| Mouth, equal-length pairs (n = 36) | 0.611 | 0.361 |
| Mouth on the 2024+ pairs (pooled held-out, n = 56) | — | 0.482 [0.357, 0.607] |
| **Brain** probe on this checkpoint's hidden states (AUC) | **0.737** [0.682, 0.792] (0.566); layers 18/18/19/26/14 | **0.706** [0.645, 0.761] (0.563); layers 24/18/19/27/14 |
| Brain probe on the frozen *base* (Phase 1.5) | 0.796 [0.746, 0.846] | — |
| Length rule (CVE pairs) | 0.805 | 0.805 |
| **Control** mouth picks "before" — non-fix (n = 226) / bug-fix (n = 42) | 0.518 / 0.690 | 0.543 [0.497, 0.588] / 0.595 [0.500, 0.686] |
| Control probe, non-fix (length rule 0.801) | 0.571 [0.504, 0.633] | 0.603 [0.561, 0.641] |
| Per fold — mouth / A/B / probe | | 0.500 / 0.500 / 0.630 · 0.587 / 0.522 / 0.728 · 0.598 / 0.543 / 0.793 · 0.511 / 0.556 / 0.667 · 0.567 / 0.511 / 0.711 |
| Per fold — training loss, first → last 10 % of steps | | 0.548→0.339 · 0.526→0.341 · 0.467→0.332 · 0.542→0.350 · 0.504→0.346 |

### Reading

1. **Supervised fine-tuning did not close the gap.** After 2 epochs of QLoRA on ~366 labelled twins per fold the tuned
   mouth reads 0.553 [0.489, 0.618] on held-out CVEs — the CI still contains chance — and the A/B forced choice is
   0.526. On the 56 newest (2024+) pairs it is 0.48. The tuned model still *says* nothing its probe cannot already read.
2. **The adapter learned the format, not the mapping.** The answer is two tokens (`Yes`/`No`, then end-of-turn). The
   per-token training loss settles at ≈ 0.34 in every fold, i.e. ≈ 0 on the end-of-turn token and ≈ ln 2 = 0.69 on
   the Yes/No token — chance level *on the training folds themselves*. Consistently, the tuned P(yes) is 0.488 on
   vulnerable vs 0.477 on fixed twins, says "yes" to 50.2 % of samples and takes only 19 distinct values across 460
   samples: the output collapsed to the label marginal (the training set is exactly balanced by construction).
   So the honest statement is *"this recipe could not make the model say what its probe reads"* — under-training and
   impossibility are not separated by this run (see the caveats for the obvious next recipe).
3. **The brain did not move either.** The probe on the tuned model's hidden states reads 0.706 [0.645, 0.761] vs 0.737
   [0.682, 0.792] on the untuned Instruct model (CIs overlap; the per-fold numbers 0.63–0.79 scatter around the untuned
   value), and the control probe is unchanged (0.60 vs 0.57). Fine-tuning on the yes/no objective neither sharpened nor
   erased the linear signal — the representation the probe uses and the output the adapter shapes are, on this evidence,
   decoupled.
4. **The Instruct checkpoint's own brain reads 0.737 — a side result that closes an old to-do.** Phases 1–2 probed the
   *base* model and questioned the *Instruct* sibling; the standing objection was that the gap might be a base-vs-instruct
   difference. Here the probe and the mouth are computed on the same Instruct weights: 0.737 [0.682, 0.792] internally
   (a few points below the base's 0.796 — instruction tuning costs some of the signal, the CIs overlap) vs 0.518 / 0.531
   spoken. Together with Codestral-22B (single checkpoint, 0.774 vs 0.54 / 0.50) the gap is now shown inside one set of
   weights in two model families.
5. **Control.** The tuned mouth on ordinary patches is 0.543 [0.497, 0.588] (chance; the length rule on those pairs is
   0.80) — the adapter did not fall back on a "shorter twin is vulnerable" shortcut either, which it could have learned
   from the training folds (79 % of CVE fixes are longer). Its equal-length score (0.361, n = 36) is below chance but
   the sample is tiny.

### Caveats specific to Phase 4

- **One model, one recipe, one seed.** The pre-registered plan said 5 seeds and a say–know closure curve; this is the
  first point of it. The recipe is deliberately light (lr 1e-4, 2 epochs, r = 16, 4-bit base, ~91 optimiser steps per
  fold). Before the null result is called "fine-tuning cannot close the gap", the notebook should be re-run with a
  recipe that at least *memorises* the training folds (lr 2e-4, 4–6 epochs, r = 32, or an A/B-contrast objective) —
  if the training loss reaches ≈ 0 and the held-out mouth is still ≈ 0.5 that is the classic memorise-but-not-generalise
  finding; if it does not, the earlier phases' probe (0.80, AUC ≈ 0.6) is simply a weak per-sample signal that 366
  examples cannot teach an adapter. Both readings are consistent with the frozen-model results.
- 4-bit base + bf16 embeddings/`lm_head` (PEFT's default fp32 up-cast of the embeddings was disabled to fit the card);
  gradient checkpointing; the loss is computed from the answer-only logits (`logits_to_keep`) — identical to
  `labels=` with `-100` on the prompt, but it does not materialise the 2 400 × 152 k logit tensor.
- The first execution of the training cell died with CUDA OOM: a stale kernel from the Qwen2.5-7B run still held
  9.6 GB of the 22 GB card for the whole run (it was not killed), and the notebook's `free()` had not released the
  untuned model. Cells 7b–7f in the notebook document the diagnosis and fix; every number above is from the second,
  complete execution. The relevant cells were typed into Colab through a browser-automation pane as `exec(base64…)`
  one-liners; the committed notebook restores the readable source (identical code) and keeps the executed outputs.
- Probe layer for the tuned model is chosen inside the training fold (no optimistic bias); the untuned-Instruct probe
  uses the same rule. Mouth prompts, clips (3 000 tokens single / 1 400 per twin in A/B) and YES/NO token sets are the
  Phase 1.5 ones.
- `tuned.mouth.post2024` is a slice of the pooled held-out scores, not a temporal split (the adapters saw pre-2024 and
  2024+ CVEs alike).

## ★★★★ PHASE 2 RESULT — does it hold in other model families? (Colab T4 + GCP L4, Sep 13–28 2026)

Prof. Yang asked for the result to be replicated outside Qwen. The same notebook template
(`code/gen_multi_model_notebooks.py` → `notebooks/xmodel_*.ipynb`) runs the identical pipeline for each
model: 228 audited CVE pairs, 4-bit base model, mean-pooled hidden states, CVE-grouped 5-fold CV with the best
layer chosen inside CV, 5,000-resample bootstrap CIs, temporal split (train < 2024, test 2024+, n = 56),
length-residualised probe, transfer of the CVE-trained probe to the 226 length-matched non-security pairs and
the 42 bug-fix pairs, and the three mouth prompts on the Instruct sibling (first-answer-token probabilities; for Codestral-22B the one
shipped checkpoint plays both roles — it has a chat template).
MAX_TOKENS = 3000 for single functions, 1400 per twin in the A/B prompt, for every model.

| | Qwen2.5-Coder-7B (Phase 1.5/1.5b) | CodeLlama-7B | Gemma-2-9B | Llama-3.1-8B | Mistral-Small-24B | CodeGemma-7B | Codestral-22B | Qwen2.5-7B (general) |
|---|---|---|---|---|---|---|---|---|
| base / instruct | Qwen2.5-Coder-7B / -Instruct | CodeLlama-7b-hf / -Instruct-hf | gemma-2-9b / gemma-2-9b-it | Llama-3.1-8B / -Instruct | Mistral-Small-24B-Base-2501 / -Instruct-2501 | codegemma-7b / codegemma-7b-it | Codestral-22B-v0.1 (single checkpoint) | Qwen2.5-7B / -Instruct |
| best layer | 24 of 28 | 26 of 32 | 21 of 42 | 14 of 32 | 17 of 40 | 13 of 28 | 21 of 56 | 27 of 28 |
| **Mouth** zero-shot / expert / A-B | 0.50 / 0.54 / 0.50 | 0.382 / 0.421 / 0.500 [0.434, 0.566] | 0.518 / 0.469 / 0.522 [0.456, 0.583] | 0.553 / 0.522 / 0.500 [0.434, 0.566] | 0.575 / 0.575 / 0.500 [0.434, 0.566] | 0.447 / 0.482 / 0.474 [0.408, 0.539] | 0.539 / 0.500 / 0.500 [0.434, 0.566] | 0.491 / 0.522 / 0.504 [0.439, 0.570] |
| Length rule (CVE pairs) | 0.805 | 0.805 | 0.805 | 0.805 | 0.805 | 0.805 | 0.805 | 0.805 |
| **Brain** probe, pairwise | **0.796** [0.746, 0.846] | **0.770** [0.715, 0.825] | **0.768** [0.711, 0.820] | **0.761** [0.706, 0.814] | **0.787** [0.735, 0.838] | **0.803** [0.752, 0.853] | **0.774** [0.721, 0.827] | **0.765** [0.708, 0.818] |
| Brain, single-sample AUC | ~0.60 | 0.578 | 0.580 | 0.576 | 0.602 | 0.594 | 0.607 | 0.587 |
| Brain, temporal (2024+, n = 56) | 0.830 [0.723, 0.920] | 0.804 [0.696, 0.911] | 0.857 [0.767, 0.946] | 0.821 [0.714, 0.911] | 0.839 [0.741, 0.929] | 0.821 [0.714, 0.911] | 0.830 [0.732, 0.920] | 0.768 [0.661, 0.875] |
| Brain, length-residualised | 0.833 [0.785, 0.879] | 0.776 [0.721, 0.829] | 0.781 [0.726, 0.833] | 0.772 [0.719, 0.825] | 0.789 [0.735, 0.840] | 0.776 [0.721, 0.831] | 0.772 [0.717, 0.825] | 0.781 [0.726, 0.833] |
| **Control** non-security patches (n = 226) | **0.606** [0.542, 0.668] | **0.628** [0.566, 0.688] | **0.591** [0.527, 0.650] | **0.597** [0.535, 0.659] | **0.644** [0.582, 0.706] | **0.631** [0.566, 0.690] | **0.637** [0.575, 0.697] | **0.619** [0.558, 0.681] |
| Control, length rule on those pairs | 0.801 | 0.801 | 0.801 | 0.801 | 0.801 | 0.801 | 0.801 | 0.801 |
| Control, bug-fix commits (n = 42) | 0.667 [0.524, 0.798] | 0.702 [0.560, 0.833] | 0.679 [0.536, 0.810] | 0.643 [0.500, 0.786] | 0.702 [0.560, 0.833] | 0.726 [0.583, 0.857] | 0.726 [0.583, 0.857] | 0.786 [0.667, 0.905] |
| Security-specific gap (CVE − non-security) | 0.190 | 0.141 | 0.177 | 0.164 | 0.143 | 0.172 | 0.137 | 0.146 |

Raw numbers: `results/xmodel/results_<model>.json`. Executed notebooks: `notebooks/xmodel_codellama7b.ipynb`,
`notebooks/xmodel_gemma2_9b.ipynb`, `notebooks/xmodel_llama31_8b.ipynb`, `notebooks/xmodel_mistral24b.ipynb`,
`notebooks/xmodel_codegemma7b.ipynb`, `notebooks/xmodel_codestral22b.ipynb`, `notebooks/xmodel_qwen25_7b.ipynb`.
The 7–9B models (incl. CodeGemma) ran on the free Colab T4; Mistral-Small-24B and Codestral-22B needed an NVIDIA L4 (24 GB) on
Colab Enterprise (GCP project `halurust-thesis`, us-east4, ~1.5 h and ~1.9 h respectively, paid from the education credit);
Qwen2.5-7B (general) was also run on the L4 for speed (~55 min).

### Reading

1. **The say–know gap is not a Qwen artefact.** In a code model with a mid-2023 training cutoff (CodeLlama),
   in a general-purpose model from a third family (Gemma-2, the family HALURust's own classifier comes from), in
   Llama-3.1-8B and in the 3× larger Mistral-Small-24B, the mouth is at chance on all three prompts while the
   probe reads 0.76–0.79 — the same shape as Qwen's 0.50 vs 0.80. Five families, eight models (every family now has
   both a code and a general member), eight times the same picture.
   Mistral-24B's yes/no prompts are the best mouth we have seen (0.575, AUC 0.54) — still far below its own probe
   (0.787) and its A/B forced choice is exactly 0.500.
   CodeGemma-7B — Prof. Yang's requested code sibling of Gemma — has the *best brain of all six* (0.803, temporal
   0.821) and a mouth *below* chance on all three prompts (0.447 / 0.482 / 0.474): the widest say–know gap so far.
   Codestral-22B — the code sibling of Mistral-Small-24B, and the one model whose brain and mouth are the *same*
   checkpoint — reads 0.774 internally and answers 0.54 / 0.50 / 0.50 (A/B exactly 0.500 again).
   Qwen2.5-7B — the *general* sibling of the original Qwen2.5-Coder-7B, added so the Qwen family has both members —
   reads 0.765 internally (best layer 27 of 28, the latest of any model) and answers 0.49 / 0.52 / 0.50.
   CodeLlama's yes/no prompts are likewise *below* chance (0.38 / 0.42): its Instruct model says "vulnerable"
   slightly more often for the *fixed* twin, i.e. it is reacting to something like code length or added checks,
   not to the vulnerability.
2. **The temporal test is strongest where it matters most.** CodeLlama's training data ends before most of the
   2024+ CVEs were disclosed, and its probe still transfers at 0.80 to those pairs. Gemma-2 (released June 2024)
   reads 0.86, Llama-3.1 (released July 2024) 0.82, Mistral-Small (January 2025) 0.84, Codestral (May 2024) 0.83 and Qwen2.5-7B (September 2024) 0.77 on the
   same 56 pairs.
   Memorised labels cannot explain this.
3. **The non-security control replicates.** On ordinary patches with the identical length pattern the length
   rule stays at 0.80 but the probe drops to 0.59–0.64 in all eight models; the ordering ordinary < bug-fix <
   security fix holds in every model. The security-specific part of the signal is 0.14–0.19 pairwise points,
   with the remaining ~0.10–0.14 being a generic "older version" sense shared across families. Mistral-24B has
   the highest control score (0.644): the bigger model has a slightly stronger generic "before/after" sense, but
   its security-specific gap (0.143) is the same size as CodeLlama's. Codestral-22B behaves like its sibling
   (control 0.637, gap 0.137 — the smallest of the eight, but within a few points of the others). Qwen2.5-7B: control
   0.619, gap 0.146; its bug-fix stratum (0.786) is the highest, but n = 42 and the CI spans 0.67–0.91.
4. **Absolute level is similar across families and sizes (0.76–0.80)** even though the models differ in size,
   corpus and cutoff; the two code-specialised 7B models (CodeGemma 0.803, Qwen 0.796) are marginally best, the two general-purpose 8–9B models are not
   behind CodeLlama, and tripling the parameter count (Mistral-24B 0.787, Codestral-22B 0.774) buys nothing. Single-sample
   AUC is modest (0.58–0.61) in all eight — the probe is a *comparative* detector. Best layer sits at 38–96% of
   depth (Qwen-Coder 24/28, CodeLlama 26/32, Gemma 21/42, Llama 14/32, Mistral 17/40, CodeGemma 13/28,
   Codestral 21/56, Qwen2.5-7B 27/28) — in the second half of the network for every model but Llama and CodeGemma.
5. **Code sibling vs general sibling inside one family (Gemma-2-9B 0.768 vs CodeGemma-7B 0.803).** The smaller
   code-tuned model reads the vulnerability slightly better internally while its Instruct mouth is slightly worse
   (0.45–0.48 vs 0.47–0.52) — code pre-training sharpens what the model *knows* without helping what it *says*.
   The second family says otherwise: Codestral-22B (0.774) reads slightly *worse* than Mistral-Small-24B (0.787) and
   its mouth is also slightly worse (0.54/0.50/0.50 vs 0.58/0.58/0.50). The third family (Qwen2.5-Coder-7B 0.796 vs
   Qwen2.5-7B 0.765) again favours the code model, by +0.031. Three within-family comparisons: +0.035, −0.013, +0.031 —
   every one inside the CIs, so "code pre-training sharpens the brain" is **not** supported as a finding; at most the
   direction leans toward code models (2 of 3) by ~3 points. Report it as a null result with that lean noted.
   The mouth is at chance in both members of every family.

### Caveats specific to Phase 2

- Gemma-2 requires eager attention (softcapping); the stock mouth cell ran out of T4 memory because it
  materialised full-vocabulary logits (256k) for all positions. The mouth was re-run keeping only the last
  position (`logits_to_keep=1`) with an OOM fallback to shorter clips that never fired (`oom_fallbacks = 0`),
  so the prompts and clips are identical to the other runs. The failed cell was removed from the notebook; a
  text cell records this.
- Same two-model-per-family design as before: brain on the base model, mouth on the Instruct sibling. The Instruct
  model's own hidden states were probed in Phase 4 for Qwen2.5-Coder-7B (0.737 [0.682, 0.792] vs 0.796 on the base;
  see the Phase 4 section) — the gap is present inside the Instruct checkpoint as well.
- Best layer is selected on the CVE pairs before the control/temporal tests; with 28–42 layers this is a mild
  optimistic bias on the CVE number only (the per-layer curves are flat near the optimum in all three models).
- Llama-3.1-8B ran without incident (128k vocab fits the T4 with the stock mouth cell).
- Mistral-Small-24B ran on a g2-standard-4 / L4 Colab Enterprise runtime (us-central1 had no L4 stock; us-east4
  did). The 94 GB boot disk could not hold the 47 GB base download, so the Hugging Face cache was symlinked to
  the 100 GB data disk and the base cache deleted before the Instruct download; otherwise the notebook is the
  stock generator output. Total ~1.5 h of L4 time.
- CodeGemma-7B: brain and mouth were computed in two kernels. The Colab runtime was recycled (browser offline for
  several days) after the brain cells had run on Sep 18; the mouth cell was re-run on Sep 22 in a fresh kernel, so
  the notebook's final `results["mouth"]` assignment raised a NameError and the JSON was assembled by hand from
  the two printed outputs (brain figures at 3 d.p.; `results/xmodel/results_CodeGemma-7B.json` `notes`). A stray
  ValueError in the extraction cell (an unnecessary base-model reload while the Instruct model still held the GPU)
  is explained by a text cell in the notebook and has no bearing on the numbers.
- Codestral-22B (Sep 22, Colab Enterprise L4, ~1.9 h): `mistralai/Codestral-22B-v0.1` ships one checkpoint that is both
  base and instruct (it has a chat template), so `MODEL_BASE == MODEL_INSTRUCT`, one 44 GB download and no cache
  deletion between the brain and mouth cells; the repo was ungated on the Hub at run time. The notebook was built from
  the Mistral-24B one (same generator cells; config + cache-symlink cell changed). One stray failed execution of the
  extraction cell (an accidental re-run, `ValueError: modules dispatched on the CPU`, 0.6 s, after the real run had
  completed) is visible in the notebook and has no bearing on the numbers. Because brain and mouth are the same
  weights, this is the first model where the say–know gap cannot be attributed to base-vs-instruct differences.
- Qwen2.5-7B (Sep 28, Colab Enterprise L4, ~55 min): `Qwen/Qwen2.5-7B` + `-Instruct`, both ungated, stock notebook
  (Mistral template with config + cache-symlink cell). The mouth cell was accidentally run twice; only the second
  run's output ([14]) is recorded (same weights, prompts and clips; first-token probabilities are deterministic).
  Best layer 27 of 28 is the last hidden layer before the output — the latest of the eight models (Coder-7B: 24 of 28).
- Still open: DeepSeek-Coder-6.7B and StarCoder2-7B (ungated, T4), and a Qwen2.5-Coder size sweep (1.5B/14B/32B)
  for a clean scale curve inside one family.

## ★★★ PHASE 1.5b RESULT — the controls: security or patch-shape? (Colab T4, Sep 2 2026)

Notebook `phase15b_controls_v2.ipynb` (Gurman's Drive, Colab id `15J_J-Bo780jl1VGs_Y_MwSuw92gbpRCO`, outputs
saved). Same 228 audited CVE pairs, same frozen Qwen2.5-Coder-7B-base (4-bit, mean-pool, MAX_TOKENS=3000),
CVE-grouped 5-fold CV, best layer again **L24 → 0.796 [0.746, 0.846]** (reproduces Phase 1.5 exactly).

**Control set (new artefact, `control_pairs.zip` + `control_meta.csv`).** From the same 160 repositories
(shallow partial clones; rust-lang/rust skipped, history too large) I mined 1,133 ordinary before/after
function pairs from commits that (a) are not any advisory/fix SHA in the sheet, its parent, or its child,
(b) contain no security vocabulary in the message (CVE, RUSTSEC, secur*, vuln*, unsound, UB, overflow, OOB,
UAF, double-free, panic, race, leak, injection, unchecked, bounds, timing, audit, unsafe, poison, validate,
traversal, permission, … full regex in `/tmp/ctrl/mine.py`), (c) are not version bumps / fmt / clippy /
typo / rename / doc / revert commits, (d) touch 1–4 non-test `.rs` files with 4–160 changed lines.
Functions enclosing each diff hunk were extracted with a brace-matching Rust item parser (fn preferred,
else the enclosing impl/struct/trait), before-text vs after-text, 150–9000 chars. From these, **226
"non-fix" pairs were delta-matched to the CVE pairs** (bins on after−before char delta; per-repo cap 5;
124 repos): after-is-longer 0.792 vs CVE fixed-is-longer 0.796; delta percentiles 10/25/50/75/90 =
−48/14/176/699/1691 vs −34/8/177/816/1917; median before-length 1600 vs 1625 chars. Length rule "shorter
twin = before" scores **0.801 on controls vs 0.805 on CVEs** — the match is tight. A secondary stratum of
42 non-security *bug-fix* commits (message has fix/bug/regression/incorrect… but no security words) was
added, mostly after-longer (0.62).

| TEST | value | 95% CI |
|---|---|---|
| CVE pairs: L24 probe picks vulnerable twin | **0.796** | [0.746, 0.846] n=228 |
| **T1 CONTROL (non-security, non-fix): same probe picks "before"** | **0.606** | [0.542, 0.668] n=226 |
| · length rule on the same control pairs | 0.801 | |
| · probe–length-rule agreement on controls | 0.637 | |
| · secondary: non-security bug-fix commits | 0.667 | [0.524, 0.798] n=42 |
| · transfer curve by layer (control "before" rate) | 0.49–0.67, mean ≈0.60, no layer near 0.80 | |
| T2 AUC CVE-vulnerable vs control-before (old vs old) | 0.798 | |
| T2 AUC CVE-fixed vs control-after (domain baseline) | 0.826 | |
| T2 AUC patch-direction (vuln−fixed) vs (before−after) | 0.610 | |
| **T3 length-residualised probe, CVE pairwise** | **0.833** | [0.785, 0.879] |
| · residualised AUC / eq-len / on control | 0.610 / 0.694 / 0.606 | |
| T4 padding placebo (159 pairs where fix was longer): vuln-pick rate orig → padded | 0.871 → 0.906 | flips 26/159 |

### Reading

1. **The probe is not a length detector.** Three independent lines: (T1) on length-matched ordinary
   patches — where the length rule still scores 0.80 — the CVE-trained probe drops to 0.61, CIs
   non-overlapping (gap 0.19); (T3) regressing log-length out of every hidden dimension *raises* the
   probe to 0.833; (T4) padding the vulnerable twin until it is the longer one does not flip the probe
   (0.87 → 0.91; a pure length detector would collapse toward 0.1). The Phase 1.5 McNemar tie was
   therefore agreement on easy pairs, not identity of mechanism.
2. **Most of the signal is specific to security fixes, not all of it.** The probe still prefers "before"
   on 61% of ordinary patches (CI excludes 0.5). Of the probe's excess over chance on CVE pairs
   (0.296), roughly a third (0.106) is present on ordinary patches — a generic "older/pre-change version"
   component (code age, style, incompleteness). Graded picture: ordinary patches 0.61 < non-security
   bug fixes 0.67 (n=42, wide) < security fixes 0.80. Report the gap (0.19) as the security-specific part.
3. **T2 is confounded and should not be used as evidence.** The CVE corpus and the control corpus are
   distinguishable as datasets (fixed-vs-after AUC 0.826 ≈ vulnerable-vs-before 0.798; margin −0.03):
   HALURust's LLM-assisted function extraction (e.g. "// ...existing code..." artefacts) vs my
   parser-based extraction. Within-pair tests (T1, T3, T4) are immune to this; single-sample cross-dataset
   AUCs are not. The pair-difference direction AUC (0.61) is the only T2 number worth mentioning, and only
   as weak support.
4. **Where the probe still struggles:** pairs where the vulnerable twin is the longer/equal one
   (≈69 of 228): implied accuracy ≈0.62. Eq-len subset 0.69 (residualised), n=36. The AUC (single-sample,
   0.60–0.61) remains modest — the knowledge is relational/pairwise more than absolute.

### Paper framing after 1.5b

"A frozen code LLM's activations linearly encode which of two Rust twins is vulnerable (0.80 pairwise,
0.83 after removing length, intact on post-cutoff CVEs), while the model's own answers are at chance.
On length-matched non-security patches from the same repositories the same probe falls to 0.61, so the
signal is predominantly about the security fix rather than patch shape — with a measurable generic
before/after component (~0.1) that any twin-based evaluation must subtract." The length-shortcut
methodological finding (0.80 free ride) stands.

### Threats / to-do for the write-up
- Control commits were filtered by message vocabulary; some may be silent security fixes → would bias
  the control *upward* (conservative for our claim). State the regex and the ±1-commit exclusion.
- Extraction pipelines differ between corpora (see T2). A cleaner future control: rebuild CVE pairs with
  the same parser, or run the control mining through HALURust's extraction prompt.
- Padding uses comment lines; mean-pooling dilutes content. Report T4 as supporting, not primary.
- Bug-fix stratum is small (42); mine more to test "security vs generic bugginess" properly.

---

## ★★ PHASE 1.5 RESULT — the say-vs-know ladder (Colab T4, Sep 1 2026)

Notebook `phase15_ladder.ipynb` in Gurman's Colab/Drive (self-contained). Same corpus (228 clean pairs,
460 samples), fresh extraction (mean-pool, MAX_TOKENS=3000), CVE-grouped CV. Mouth = Qwen2.5-Coder-7B-
**Instruct** answer-token probabilities; brain = linear probe on frozen Qwen2.5-Coder-7B-base hidden states.

| Method (same data, same metric) | Overall pw | Eq-len pw | AUC |
|---|---|---|---|
| length floor | 0.805 | 0.681 | 0.544 |
| MOUTH: zero-shot yes/no | 0.496 | 0.583 | 0.502 (raw acc 0.515) |
| MOUTH: expert-role yes/no | 0.535 | 0.583 | 0.498 (raw acc 0.507) |
| MOUTH: A/B forced choice (both twins shown) | 0.504 | 0.528 | — (temporal 0.500) |
| **BRAIN: linear probe, L24** | **0.796** | 0.681 | 0.600 |

**Statistics:** probe overall 0.796, 95% CI [0.746, 0.846], n=228. Temporal (train <2024 → test 2024+)
**0.830**, CI [0.723, 0.920], n=56. Eq-len 0.681, CI [0.528, 0.819], sign-test p=0.035. McNemar
probe-vs-length-rule p=0.885 (now explained by 1.5b: shared easy pairs, different mechanism).

### The three claims, ranked by strength (updated)

1. **THE SAY–KNOW GAP (rock solid, headline).** Mouth 0.50 on every prompt incl. twin forced choice;
   brain 0.796 [0.746, 0.846] on identical data/metric/model family. Mechanism-level explanation of
   HALURust's code+FT ≈ 50% ablation.
2. **No memorization (solid).** Temporal probe 0.830 [0.723, 0.920]; mouth temporal 0.500.
3. **Probe vs the length shortcut — now largely closed (1.5b).** Not a length detector (T1/T3/T4);
   predominantly security-specific with a ~0.1 generic before/after component.

---

## PHASE 1 RESULT (Aug 28 2026, `phase1_probing_sc.ipynb`)

7B base, 4-bit, 460×29×3584, MAX_TOKENS=4096: overall pairwise 0.818 (L24), eq-len 0.792 (L19),
AUC 0.599, temporal 0.821, never-patched stratum 0.800. 0.5B CPU pilot: 0.708/0.730/0.586.
Floors: length 0.805/0.681, unsafe 0.502, tfidf 0.638/0.611; random-split AUC 0.092 (leakage exhibit).
Error analysis: worst pairs skew panic-safety/double-free (scratchpad CWE-415, ordered-float CWE-416,
smallvec CWE-787, tokio CWE-362); best: autorand CWE-908 +0.93, Libra Core CWE-701 +0.94.

## Key methodological finding (reportable)

**The pairwise twin metric does not cancel length** — fixes add code; "shorter twin is vulnerable"
scores ~0.81 alone (0.80 on ordinary patches too). Report overall + equal-length + AUC + a
non-security-patch control, with CIs.

## Remaining work

- **Phase 2**: difference-vector direction, cross-CWE clustering, project-held-out split; bigger bug-fix
  stratum (security vs generic bugginess); rebuild controls with identical extraction.
- **Phase 3**: activation steering (optional).
- **Phase 4 (training, GCP `halurust-thesis`)**: first point done (Sep 29: QLoRA on Qwen2.5-Coder-7B-Instruct, one
  recipe, one seed — mouth 0.55, probe 0.71, see the Phase 4 section). Still to do: a recipe that memorises the training
  folds (lr 2e-4, 4–6 epochs, r = 32, or an A/B-contrast objective), 5 seeds, the say–know closure curve against the
  frozen-probe ceiling 0.80 (0.83 residualised), contrastive twin encoder.
- Prior-art pass done (LPASS 2505.24451; code-correctness probing 2606.14530; circuit analysis 2605.29901;
  RustMizan 2607.04729). None: say-vs-know for security, audited real-CVE pairs, temporal split, Rust,
  non-security-patch control.

## RQ status

1. Internal linear signal? **Yes — 0.80 pairwise, CI [0.75, 0.85]; 0.83 length-residualised.**
2. Where? **Mid-late layers (L19–L24 of 28), mean-pool ≫ last-token.**
3. Generalization? **Unseen CVEs yes; post-cutoff yes (0.83); projects/CWE pending.**
3b. Say–know gap? **Measured: mouth 0.50 on all prompts vs brain 0.80. The central result.** Inside the Instruct
    checkpoint itself: brain 0.74 vs mouth 0.52 (Phase 4 baseline).
3c. Security or patch shape? **Predominantly security: 0.80 on CVE pairs vs 0.61 on length-matched
    ordinary patches (length rule 0.80 on both); residual generic component ≈0.1.**
4. Does training move the mouth or the brain? **First point (Phase 4): neither — QLoRA on the yes/no task leaves the
   mouth at 0.55 [0.49, 0.62] and the probe at 0.71 [0.65, 0.76]; the adapter learned the answer format and the label
   marginal only. Stronger recipe + seeds pending.**
5–6. Pending.

## Artefacts
- `phase15b_controls_v2.ipynb` (self-contained: CVE pairs + metadata + control pairs embedded; two data
  cells kept under ~800 KB each — a single 1.4 MB cell + "Run all" crashed the Colab runtime three times).
- `control_pairs.zip` (Before/, After/, control_meta.csv: id, repo, sha, date, cat, subject, files,
  diff_lines, before_chars, after_chars, delta), `phase15b_results.json`.
- Mining code: `/tmp/ctrl/{clone.py, rustitems.py, mine.py, sample.py, gen15b.py}` (session container).
