# Probing Study — Design + Phase 1, 1.5, 1.5b & 2 RESULTS (rev. 6, Sep 15 2026)

Working title: **"Beyond What Code LLMs Say: Probing Internal Representations for Rust Vulnerability Detection."**

## ★★★★ PHASE 2 RESULT — does it hold in other model families? (Colab T4, Sep 13–15 2026)

Prof. Yang asked for the result to be replicated outside Qwen. The same notebook template
(`code/gen_multi_model_notebooks.py` → `notebooks/xmodel_*.ipynb`) runs the identical pipeline for each
model: 228 audited CVE pairs, 4-bit base model, mean-pooled hidden states, CVE-grouped 5-fold CV with the best
layer chosen inside CV, 5,000-resample bootstrap CIs, temporal split (train < 2024, test 2024+, n = 56),
length-residualised probe, transfer of the CVE-trained probe to the 226 length-matched non-security pairs and
the 42 bug-fix pairs, and the three mouth prompts on the Instruct sibling (first-answer-token probabilities).
MAX_TOKENS = 3000 for single functions, 1400 per twin in the A/B prompt, for every model.

| | Qwen2.5-Coder-7B (Phase 1.5/1.5b) | CodeLlama-7B | Gemma-2-9B |
|---|---|---|---|
| base / instruct | Qwen2.5-Coder-7B / -Instruct | CodeLlama-7b-hf / -Instruct-hf | gemma-2-9b / gemma-2-9b-it |
| best layer | 24 of 28 | 26 of 32 | 21 of 42 |
| **Mouth** zero-shot / expert / A-B | 0.50 / 0.54 / 0.50 | 0.382 / 0.421 / 0.500 [0.434, 0.566] | 0.518 / 0.469 / 0.522 [0.456, 0.583] |
| Length rule (CVE pairs) | 0.805 | 0.805 | 0.805 |
| **Brain** probe, pairwise | **0.796** [0.746, 0.846] | **0.770** [0.715, 0.825] | **0.768** [0.711, 0.820] |
| Brain, single-sample AUC | ~0.60 | 0.578 | 0.580 |
| Brain, temporal (2024+, n = 56) | 0.830 [0.723, 0.920] | 0.804 [0.696, 0.911] | 0.857 [0.767, 0.946] |
| Brain, length-residualised | 0.833 [0.785, 0.879] | 0.776 [0.721, 0.829] | 0.781 [0.726, 0.833] |
| **Control** non-security patches (n = 226) | **0.606** [0.542, 0.668] | **0.628** [0.566, 0.688] | **0.591** [0.527, 0.650] |
| Control, length rule on those pairs | 0.801 | 0.801 | 0.801 |
| Control, bug-fix commits (n = 42) | 0.667 [0.524, 0.798] | 0.702 [0.560, 0.833] | 0.679 [0.536, 0.810] |
| Security-specific gap (CVE − non-security) | 0.190 | 0.141 | 0.177 |

Raw numbers: `results/xmodel/results_CodeLlama-7B.json`, `results/xmodel/results_Gemma-2-9B.json`.
Executed notebooks: `notebooks/xmodel_codellama7b.ipynb`, `notebooks/xmodel_gemma2_9b.ipynb`.

### Reading

1. **The say–know gap is not a Qwen artefact.** In a code model with a mid-2023 training cutoff (CodeLlama)
   and in a general-purpose model from a third family (Gemma-2, the family HALURust's own classifier comes from),
   the mouth is at chance on all three prompts while the probe reads 0.77 — the same shape as Qwen's 0.50 vs 0.80.
   CodeLlama's yes/no prompts are actually *below* chance (0.38 / 0.42): its Instruct model says "vulnerable"
   slightly more often for the *fixed* twin, i.e. it is reacting to something like code length or added checks,
   not to the vulnerability.
2. **The temporal test is strongest where it matters most.** CodeLlama's training data ends before most of the
   2024+ CVEs were disclosed, and its probe still transfers at 0.80 to those pairs. Gemma-2 (released June 2024)
   reads 0.86 on the same 56 pairs. Memorised labels cannot explain this.
3. **The non-security control replicates.** On ordinary patches with the identical length pattern the length
   rule stays at 0.80 but the probe drops to 0.59–0.63 in all three models; the ordering ordinary < bug-fix <
   security fix holds in every model. The security-specific part of the signal is 0.14–0.19 pairwise points,
   with the remaining ~0.10–0.13 being a generic "older version" sense shared across families.
4. **Absolute level is similar across families (0.77–0.80)** even though the models differ in size, corpus and
   cutoff; the code-specialised Qwen is marginally best. Single-sample AUC is modest (~0.58) in all three —
   the probe is a *comparative* detector.

### Caveats specific to Phase 2

- Gemma-2 requires eager attention (softcapping); the stock mouth cell ran out of T4 memory because it
  materialised full-vocabulary logits (256k) for all positions. The mouth was re-run keeping only the last
  position (`logits_to_keep=1`) with an OOM fallback to shorter clips that never fired (`oom_fallbacks = 0`),
  so the prompts and clips are identical to the other runs. The failed cell was removed from the notebook; a
  text cell records this.
- Same two-model-per-family design as before: brain on the base model, mouth on the Instruct sibling. Probing
  the Instruct model's own hidden states is still on the to-do list (planned check that base and instruct
  probes agree).
- Best layer is selected on the CVE pairs before the control/temporal tests; with 28–42 layers this is a mild
  optimistic bias on the CVE number only (the per-layer curves are flat near the optimum in all three models).
- Llama-3.1-8B is queued (gated licence; notebook `xmodel_llama31_8b.ipynb` ready). DeepSeek-Coder-6.7B and
  StarCoder2-7B are ungated and can follow without any setup.

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
- **Phase 4 (training, GCP `halurust-thesis`, $100 credit intact, GPUS_ALL_REGIONS=1, Vertex enabled)**:
  QLoRA fine-tune → re-probe (does training move the brain or the mouth?); say–know closure curve —
  frozen-probe 0.80 (0.83 residualised) is the pre-registered ceiling; contrastive twin encoder. 5 seeds.
  Safe to start now that the controls passed: a fine-tune can be evaluated on the control set too.
- Prior-art pass done (LPASS 2505.24451; code-correctness probing 2606.14530; circuit analysis 2605.29901;
  RustMizan 2607.04729). None: say-vs-know for security, audited real-CVE pairs, temporal split, Rust,
  non-security-patch control.

## RQ status

1. Internal linear signal? **Yes — 0.80 pairwise, CI [0.75, 0.85]; 0.83 length-residualised.**
2. Where? **Mid-late layers (L19–L24 of 28), mean-pool ≫ last-token.**
3. Generalization? **Unseen CVEs yes; post-cutoff yes (0.83); projects/CWE pending.**
3b. Say–know gap? **Measured: mouth 0.50 on all prompts vs brain 0.80. The central result.**
3c. Security or patch shape? **Predominantly security: 0.80 on CVE pairs vs 0.61 on length-matched
    ordinary patches (length rule 0.80 on both); residual generic component ≈0.1.**
4–6. Phases 2–4 pending.

## Artefacts
- `phase15b_controls_v2.ipynb` (self-contained: CVE pairs + metadata + control pairs embedded; two data
  cells kept under ~800 KB each — a single 1.4 MB cell + "Run all" crashed the Colab runtime three times).
- `control_pairs.zip` (Before/, After/, control_meta.csv: id, repo, sha, date, cat, subject, files,
  diff_lines, before_chars, after_chars, delta), `phase15b_results.json`.
- Mining code: `/tmp/ctrl/{clone.py, rustitems.py, mine.py, sample.py, gen15b.py}` (session container).
