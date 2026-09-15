# Next step — replicating across model families (plan, Sep 11 2026; status updated Sep 15)

**Status (Sep 15):** CodeLlama-7B and Gemma-2-9B done — both reproduce the Qwen pattern (mouth at chance, probe 0.77, control 0.59–0.63). Numbers and reading in `01_probing_study_design_and_results.md` (Phase 2). Llama-3.1-8B notebook is ready and waits on the gated-licence approval.

Prof. Yang asked for the result to be tested on other models (Mistral, Code Llama, GPT, Llama 3, …).

**Constraint that shapes the choice.** The "brain" measurement needs the model's hidden states, so it
only works on open-weight models we can load. Closed models (GPT-4o/5, Gemini) can only provide the
"mouth" number; that is still useful as a frontier baseline, but cannot replace the open models.

**Compute.** Free Colab T4 (15 GB) handles ≤ ~14B in 4-bit. The $100 GCP education credit buys roughly
25 A100-hours or 100 L4-hours — enough for a couple of 22–32B models, not 70B.

**What we want the model set to vary.** Code-specialised vs general; different pre-training corpora;
an old training cutoff (strongest no-memorisation test); several sizes within one family (does the
say–know gap grow or shrink with scale); a direct link to HALURust's own model family (Gemma).

| Priority | Model (base + instruct where it exists) | Why | Where |
|---|---|---|---|
| 1 | Qwen2.5-Coder 1.5B and 14B (7B done) | scale curve inside one family | Colab T4 |
| 2 | CodeLlama-7B (+Instruct) | training data ends mid-2023 → most CVEs post-cutoff; cleanest no-memorisation test | Colab T4 |
| 3 | Llama-3.1-8B (+Instruct) | general-purpose, non-code reference | Colab T4 (gated) |
| 4 | CodeGemma-7B / Gemma-2-9B (+it) | HALURust's classifier was Gemma-7B | Colab T4 (gated) |
| 5 | DeepSeek-Coder-6.7B (base + instruct) | second strong code family, different corpus | Colab T4 |
| 6 | StarCoder2-7B | training data (The Stack v2) is public → contamination checkable; base only | Colab T4 |
| 7 | Mistral-7B-v0.3 (+Instruct) | second general family | Colab T4 (gated) |
| GCP | Qwen2.5-Coder-32B-Instruct, Codestral-22B | does it hold at scale; ~$20–30 of credit | GCP L4/A100 |
| mouth only | Gemini 2.5 Flash/Pro via Vertex (credit-covered); GPT-4o/5 if a key is available | frontier mouth baseline | API |

**Per model, run the same three measurements** as for Qwen-7B: best-layer probe on the 228 CVE pairs
(CVE-grouped CV, bootstrap CIs, temporal split), the same probe transferred to the 226 length-matched
control pairs, and the three mouth prompts on the instruct sibling. Each model yields one row of the
existing table, so the paper gets a single cross-model figure. Also probe the *instruct* model's own
hidden states (not only the base model's) so brain and mouth are measured on identical weights; check
on Qwen that base and instruct probes agree.

**Needed from Gurman:** accept the Llama, Gemma and Mistral licences on Hugging Face and provide a read
token for the Colab config; an OpenAI key only if GPT is wanted. Gemini needs nothing extra (Vertex AI
is already enabled on project `halurust-thesis`).
