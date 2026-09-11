# Report Generation — Prompting Strategy Decisions (Stage 2)

> Historical note (Aug 26 2026). This note was written when the plan was still to extend HALURust's
> report-generation pipeline. The project pivoted to the probing study (`01_…`) shortly afterwards;
> the notes are kept because the leakage critique and the "identical prompt for both classes" rule
> carried over, and because the report-generation ablation remains a possible follow-up.

Status as of this note: **dataset complete (251 pairs). Stage 2 not yet started.**
Companion to `07_halurust_v2_roadmap.md` and `04_extraction_methodology_and_audit.md`.

---

## Two papers Prof. Yang forwarded

### 1. Cognitive Prompting (Kramer & Baumann, arXiv:2410.02953v3, Nov 2024)

Eight "cognitive operations" — goal clarification, decomposition, filtering, reorganization,
pattern recognition, abstraction, generalization, integration. Three variants: **D-CP**
(fixed sequence), **SA-CP** (model selects its own next operation), **H-CP** (SA-CP plus
few-shot summaries of previously *correct* solutions). Evaluated on GSM8K only, with
LLaMA 3.1, Gemma 2 and Qwen 2.5 at two sizes each. H-CP best (~95% on LLaMA 70B).
Most frequent self-selected sequence: goal clarification → decomposition → pattern recognition.

### 2. Beyond Functional Correctness (Liu et al., arXiv:2404.00971v3, Jan 2026)

Taxonomy of hallucinations in **LLM-generated code** — 3 primary and 12 specific categories,
via thematic analysis. Requirement Conflicting ~39.6%, Code Inconsistency ~25.5%
(largest sub-type: Undefined Variables, 16.91%), Knowledge Conflicting ~33%. Also tests
three training-free mitigations.

**Table IV is the number that matters for us:**

| Strategy | pass@1 | hallucinatory samples |
|---|---|---|
| Origin | 61.59 | 26.09% |
| Self-Refine | 54.27 (−7.3) | 13.91% (−12.2) |
| CoT | 51.83 (−9.8) | 15.65% (−10.4) |
| RAG (CoderEval) | 26.52 (+11.7) | 20.14% (−22.9) |

---

## The central tension (decision rationale)

**Cognitive prompting is built to improve reasoning. HaluRust depends on hallucination as
the detection signal.** The pipeline asserts a vulnerability exists and classifies on how the
model confabulates when there isn't one. A structured-reasoning method that suppresses
confabulation makes safe-code and vulnerable-code reports *more alike* and can degrade
detection.

Liu et al.'s CoT result is empirical support: chain-of-thought roughly halved the
hallucination rate. CP is in the same family.

**This makes CP a good ablation, not a good upgrade.** Every outcome is informative:

| Outcome under CP | What it means |
|---|---|
| Detection degrades | Evidence the signal really is hallucination → answers roadmap RQ1 |
| Detection unchanged | Signal is something else (lexical hedging, prompt provenance) → supports the §2.1 leakage critique |
| Detection improves | Structured reports are more comparable, less noise |

## Decisions taken

1. **Keep CO-STAR as the baseline; add CP as a second prompt condition.** Prompt strategy
   becomes an independent variable rather than a convenience choice.
2. **Order of work:** D-CP first (deterministic, cheapest, directly comparable) → SA-CP
   second (log the chosen operation sequence per sample) → H-CP only if a success proxy is
   implemented.
3. **H-CP does not transfer as-is.** It bootstraps from *correct* solutions; GSM8K has a
   checkable answer, vulnerability reports do not. Proposed proxy: a report counts as
   correct if its claimed location overlaps the actual patch hunk — computable from the fix
   commits, and it makes roadmap RQ4 (localization) the selection criterion.
4. **Log the SA-CP operation sequence as a feature.** "Does the model choose different
   cognitive operations for vulnerable vs safe code?" is a compact, low-dimensional signal
   nobody has tried, and possibly stronger than report text.
5. **Adopt Liu et al.'s taxonomy as the labelling scheme** for generated reports, adapted:
   Requirement Conflicting → report claims behaviour the code doesn't have;
   Code Inconsistency → report cites a variable or line that isn't there;
   Knowledge Conflicting → report misstates Rust/API semantics.
   *No hallucination taxonomy exists for vulnerability reports — this is a contribution.*
6. **Promote the groundedness check to a first-class detector.** Do identifiers cited in the
   report actually exist in the code? Deterministic, zero model cost, and Liu et al.'s largest
   single sub-type (Undefined Variables, 16.91%) is the citation for it.

## Non-negotiable for Stage 2

- **Identical prompt for both classes. No CVE description, ever.** This is RQ1. The original
  paper injected the real CVE description for vulnerable samples at training time but not at
  test time — the leakage that may explain their whole result.
- **Cache by `hash(model, prompt, code)`** so a Colab disconnect never costs money twice.
- **K > 1 samples at temperature > 0**, required for the self-consistency detector (roadmap §3B).
- **Log at generation time:** raw report, model + pinned version, prompt variant, temperature,
  sample index, code hash, and (for SA-CP) the operation sequence. Not capturing this means
  paying to regenerate.

## Pre-flight items before spending credits

1. **Re-derive the `Reference Commit` column for the pre-existing rows.** *(Done — `02_…`.)*
2. **Run rustfmt over both sides of every pair** — removes the formatting confound.
3. **Decide on hard negatives.** Currently 1:1 vulnerable/fixed, which is the §2.4 critique.
   Adding untouched functions from the same files is far easier now than later; if skipped,
   say so deliberately and report prevalence-adjusted precision.
