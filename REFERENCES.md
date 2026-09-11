# References

## The paper being extended
- **HALURust: Exploiting Hallucinations of Large Language Models to Detect Vulnerabilities in Rust.** arXiv:2503.10793 (2025). https://arxiv.org/abs/2503.10793 — CO-STAR report prompts, fine-tuned Gemma-7B classifier, 77.3% F1; ablation code+FT ≈ 50% vs report+FT ≈ 75%.

## Model
- **Qwen2.5-Coder Technical Report.** Hui et al., arXiv:2409.12186 (2024). https://arxiv.org/abs/2409.12186 — `Qwen/Qwen2.5-Coder-7B` (brain) and `Qwen/Qwen2.5-Coder-7B-Instruct` (mouth), loaded in 4-bit.
- **QLoRA: Efficient Finetuning of Quantized LLMs.** Dettmers et al., arXiv:2305.14314 (2023). https://arxiv.org/abs/2305.14314 — bitsandbytes 4-bit loading used here; planned fine-tuning method for Phase 4.

## Linear probing and "latent knowledge"
- **Understanding intermediate layers using linear classifier probes.** Alain & Bengio, arXiv:1610.01644 (2016). https://arxiv.org/abs/1610.01644 — the linear-probe method.
- **Designing and Interpreting Probes with Control Tasks.** Hewitt & Liang, EMNLP 2019, arXiv:1909.03368. https://arxiv.org/abs/1909.03368 — why probes need controls; motivates our length/patch-shape controls.
- **Probing Classifiers: Promises, Shortcomings, and Advances.** Belinkov, Computational Linguistics 48(1), 2022, arXiv:2102.12452. https://arxiv.org/abs/2102.12452 — survey and caveats.
- **Discovering Latent Knowledge in Language Models Without Supervision.** Burns et al., ICLR 2023, arXiv:2212.03827. https://arxiv.org/abs/2212.03827 — models can internally represent truth that their outputs do not state.
- **The Internal State of an LLM Knows When It's Lying.** Azaria & Mitchell, EMNLP Findings 2023, arXiv:2304.13734. https://arxiv.org/abs/2304.13734 — hidden-state classifiers for statement truth; closest analogue to our say-vs-know framing.
- **The Geometry of Truth: Emergent Linear Structure in LLM Representations of True/False Datasets.** Marks & Tegmark, arXiv:2310.06824 (2023). https://arxiv.org/abs/2310.06824 — linear truth directions; basis for the Phase 2 difference-vector analysis.

## Probing / interpretability applied to code models (prior art checked Sep 1 2026)
- **LPASS** — linear probes for pruning/analysis of code LLMs on C/C++ vulnerability data. arXiv:2505.24451 (2025). https://arxiv.org/abs/2505.24451
- **Code Correctness Is Linearly Decodable.** arXiv:2606.14530 (2026). https://arxiv.org/abs/2606.14530 — length-residualised probes (AUC 0.84 raw vs 0.66 residualised); precedent for our Test 3.
- **Circuit-level analysis of code models on security tasks.** arXiv:2605.29901 (2026). https://arxiv.org/abs/2605.29901
- None of these run a say-vs-know comparison, an audited real-CVE corpus, a temporal split, a non-security-patch control, or Rust.

## Rust vulnerability detection and datasets
- **RustMizan** — agentic Rust vulnerability detection (agents 56–65%). arXiv:2607.04729 (2026). https://arxiv.org/abs/2607.04729
- **RustXec.** MSR 2026 (Rust vulnerability/execution dataset).
- **RustSec Advisory Database.** https://github.com/rustsec/advisory-db — source of advisory ↔ CVE aliases, `patched` ranges and dates used in the commit audit.
- **crates.io API** — `https://crates.io/api/v1/crates/<name>` for repository resolution.

## Vulnerability-dataset quality and evaluation methodology
- **Vulnerability Detection with Code Language Models: How Far Are We? (PrimeVul).** Ding et al., ICSE 2025, arXiv:2403.18624. https://arxiv.org/abs/2403.18624 — pairwise (paired-function) evaluation and label-noise findings; our pairwise metric follows this framing.
- **CleanVul: Automatic Function-Level Vulnerability Detection in Code Commits Using LLM Heuristics.** Li et al., arXiv:2411.17274 (2024). https://arxiv.org/abs/2411.17274 — noise in commit-derived vulnerability labels.
- **Data Quality for Software Vulnerability Datasets.** Croft, Babar & Kholoosi, ICSE 2023, arXiv:2301.05456. https://arxiv.org/abs/2301.05456 — motivates the full reference-commit audit.

## Hallucination and prompting papers forwarded by Prof. Yang (Stage 2 notes)
- **Cognitive Prompting in LLMs.** Kramer & Baumann, arXiv:2410.02953 (2024). https://arxiv.org/abs/2410.02953
- **Exploring and Evaluating Hallucinations in LLM-Powered Code Generation ("Beyond Functional Correctness").** Liu et al., arXiv:2404.00971 (2024). https://arxiv.org/abs/2404.00971
- **SelfCheckGPT.** Manakul et al., arXiv:2303.08896 (2023). https://arxiv.org/abs/2303.08896 — self-consistency as a hallucination signal (candidate follow-up B in the roadmap).

## Statistics used
- Bootstrap percentile confidence intervals (5,000 resamples over pairs) for every pairwise accuracy.
- McNemar's exact test (binomial on discordant pairs) for probe vs. length rule.
- Exact sign test for the equal-length subset vs. chance.
- ROC-AUC (single-sample) alongside pairwise accuracy.
