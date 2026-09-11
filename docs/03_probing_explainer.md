# The Probing Study, Explained Simply (written Aug 28 2026, before Phase 1 ran)

> Historical note: this explainer was written when the plan was drafted. Numbers quoted here are the
> *pilot* floors measured on a 0.5B model; the final figures are in `01_probing_study_design_and_results.md`.
> Step 0's `rustfmt` normalisation was not applied in the end (fragments do not always parse); the
> length-matched control and padding placebo took its place.

## One paragraph

We have ~250 pairs of Rust functions — each pair is a real security bug (CVE) and its official repair,
nearly identical otherwise. We show both versions to a frozen code LLM and ask: *does something inside the
model's "brain" react differently to the buggy version, even when its spoken answer can't tell them apart?*
If yes, the model internally understands Rust security better than its answers reveal; we measure where that
understanding lives (which layer), verify it isn't an artifact, and then test what fine-tuning does to it.

## The steps and the terms

**Step 0 — clean data.** Drop the audit-flagged pairs (wrong fix commits). *CVE* = a specific real bug's
public ID; *CWE* = its category (buffer overflow, use-after-free…).

**Step 1 — record thoughts.** Feed all functions through frozen Qwen2.5-Coder-7B. A *hidden state*
(*activation*) is the model's mid-computation understanding, written as ~3,584 numbers; there is one per
*layer* (28 stacked processing stages — early = syntax, deep = meaning). *Frozen* = read-only, we never
modify the model — so whatever we find was already there from pretraining.

**Step 2 — the probe.** A *probe* is a deliberately tiny classifier (logistic regression — a straight line)
that tries to read "vulnerable / safe" off the hidden state. It must be dumb: if a straight line can
separate the classes, the separation already existed in the model's thought. One probe per layer →
*accuracy-by-layer curve* (AUC: chance a random buggy sample outscores a random safe one; 0.5 = coin flip).

**Step 3 — honest splitting.** *CVE-grouped split*: both twins of a pair always stay together in train or
test — twins are ~87% identical, and a careless random split scores **below chance** because the model sees
the near-identical twin with the opposite label. Also project-grouped and temporal splits.

**Step 4 — fair fights.** *Floors*: simple rules the probe must beat (length, `unsafe` keyword, TF-IDF).
*Pairwise ranking* (headline metric): show an unseen pair, ask "which twin is buggy?" — shared style and
crate cancel inside the comparison (length, we later found, does *not* cancel: fixes add code). Also compare
against the model's spoken answers under several prompts plus its yes-token probability, so no one can say
we handicapped the mouth.

**Step 5 — lie detectors.** *Patchedness control*: before/after pairs from ordinary non-security commits in
the same repos — if the probe fires on those too, it learned "patch style," not security. *Placebo pairs*:
pairs with near-identical bodies — above-chance there = leakage, stop and debug.

**Step 6 — memorization check.** Old CVEs may be in the model's training data. *Temporal split*: train on
pre-2024, test on the ~56 post-2024 pairs the model cannot have seen. Holds → understanding; collapses →
memory. Both are findings.

**Step 7 — geometry (Phase 2).** Subtract the pair's two hidden states → a *difference vector* = what changed
in the model's mind when the bug was fixed. Averaged: the *security-difference direction*. Does it point out
the buggy twin in unseen CVEs? Shared across CWE families or separate per family?

**Step 8 — steering (Phase 3, risky).** Nudge a safe function's hidden state along that direction
mid-computation; if the spoken answer flips to "vulnerable" (more with a bigger nudge), the model *uses* the
signal — causation, not correlation.

**Step 9 — training (Phase 4, uses the $100 GCP credit).** *Fine-tuning* = actually changing the model;
*QLoRA* = the cheap way. Fine-tune to answer vulnerable/safe, then re-scan the layers: did training grow the
internal signal, or only teach the mouth to say what the brain knew? Explains HALURust's own mystery
(code+FT ≈ 50%, reports+FT ≈ 75%). Always several seeds → error bars.

## Decision rule (pre-committed)

Pairwise ranking under grouped CV beats the strongest floor at some layer → "the model knows more than it
says." Otherwise → "the security signal in representations is shallow." Either way the controls make it
publishable.
