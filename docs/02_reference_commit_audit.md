# `Reference Commit` Audit — All 251 Rows (Aug 26 2026, revised after a second pass)

Machine verification of every SHA in `Gurman_Halurust_Combined_Dataset_Till_Date.xlsx`.
Supersedes the sampled 19-row audit in `04_extraction_methodology_and_audit.md` §2.1.
Deliverable: `data/Halurust_SHA_audit.xlsx` (the sheet plus 10 audit columns).

**Method.** Crate → repo resolved via crates.io `repository` (168 crates) with RustSec/manual
fallbacks; every SHA fetched with `git fetch --depth=2 https://github.com/<repo> <sha>` (no API
token, no rate limit); commit subject, date, parent count and per-file diffstat compared against
the RustSec advisory that lists the CVE in its `aliases`. 224/251 rows map to a RustSec advisory;
the other 27 are application-level CVEs (Frontier, SWHKD, Skytable, Apollo Router, ClamAV, Cargo,
Occlum …) with no advisory to compare against.

## Headline

| Verdict | Rows |
|---|---|
| Verified — commit matches the advisory | **221** |
| **Wrong commit** | **11** |
| **SHA not found in the repo** | **4** |
| Correct fix but no Rust delta | 2 |
| Needs review | 11 |
| Correct SHA, wrong `Program / Crate` label | 2 |

The column is in far better shape than the earlier sample suggested — the crates named as wrong
in the previous audit (qwutils, postscript, marc, cdr, ms3d …) now carry correct fix commits.
**calamine is the one survivor from that list.**

## Confidence and limits of this audit

| How each row was checked | Rows |
|---|---|
| Advisory matched (subject + diffstat vs. RustSec advisory text) | 202 |
| Diff inspected line-by-line | 20 |
| Subject only (no advisory exists for the CVE) | 25 |
| Could not verify (SHA absent from the repo) | 4 |

A second pass re-tested the audit itself:

- **Alias mapping re-checked for all 11 wrong rows** — every one maps to an advisory that lists
  the CVE in `aliases`, and the crate names agree (except row 133, already flagged).
- **Strict re-sweep of the 221 "OK" rows** (commit >120 d after the advisory, >365 d before,
  generic merge/release subject, >20 files, no `.rs`) surfaced 19 candidates; 17 were genuine
  (GitHub's "Merge commit from fork" is the standard subject for a private security-fork merge,
  and `Merge pull request from GHSA-…` is the wasmtime/cranelift fix pattern). Two were
  regraded — rows 74 and 215, now REVIEW.
- **12 randomly sampled OK rows had their diffs read in full** — all 12 implement exactly what
  their advisory describes (sodiumoxide `memcmp(self, self)` → `memcmp(self, other)`, std Zip
  `self.len += 1`, cdr `set_len` → `resize`, …). No false "OK" found in the sample.
- **One mapping bug found and fixed:** row 74 (CVE-2020-26235) was matched to chrono's
  RUSTSEC-2020-0159, which lists the CVE under `related`, instead of the `time` advisory
  RUSTSEC-2020-0071. 14 other `related`-matched rows are the `rust/std` advisories whose ID *is*
  the CVE ID, so they were correct.

**What this audit does not establish:** that the parent commit is the exact version the CVE
describes, for the 25 subject-only rows and wherever the fix landed long after disclosure.

## Wrong commits (11)

| Row | CVE | Crate | What the SHA actually is |
|---|---|---|---|
| 2 | CVE-2025-62711 | wasmtime | 65-file "Replace setjmp/longjmp usage" refactor, Sep 2025. Advisory (RUSTSEC-2025-0112) was patched in 38.0.3. |
| 50 | CVE-2023-49092 | rsa | 31-file `num-bigint-dig` → `crypto-bigint` migration, Feb 2025. Marvin-attack advisory has **no** upstream patch. |
| 87 | CVE-2020-36219 | atomic-option | A **2015** commit — five years before the advisory, which was never patched. |
| 133 | CVE-2022-39252 | matrix-sdk-crypto | Test-only commit. RUSTSEC-2022-0085 explicitly names fix commit `093fb5d0`. |
| 159 | CVE-2019-16882 | string-interner | 2023 performance commit ("Faster encoding for lengths in BufferBackend"). |
| 213 | CVE-2021-30454 | outer_cgi | 2023 merge fixing a *different* bug (`read_length` wrong size >128). Advisory names `dd59b306`. |
| 216 | CVE-2021-29938 | slice-deque | Diff fixes `tail_head_slice`; the CVE is the `drain_filter` double-drop, never patched. |
| 220 | CVE-2021-29932 | parse_duration | 2019 `isize` edge-case commit; the big-exponent DoS was never patched. |
| 237 | CVE-2021-26951 | calamine | `bump v0.17.0` — Cargo.toml + Changelog only. |
| 249 | CVE-2020-36464 | heapless | Release merge "Release v0.6.1" — CHANGELOG + Cargo.toml only. |
| 250 | CVE-2020-35925 | magnetic | 2025 eight-file rewrite; advisory was patched in 2.0.1 (2020). |

## SHA not found in the repository (4)

- **Row 11** CVE-2025-5791 `users` — not in `ogham/rust-users`; RUSTSEC-2025-0040 was never patched, so no fix commit exists.
- **Row 175** CVE-2021-24117 Teaclave SGX SDK — not in either `apache/(incubator-)teaclave-sgx-sdk`.
- **Row 186** CVE-2021-32715 "hper crate" — not in `hyperium/hyper`. Duplicate of row 200, which carries the correct `1fb719e0`.
- **Row 240** CVE-2020-36441 `abox` — repo `oberien/abox` no longer exists; unverifiable.

## Correct fix, but no Rust pair extractable (2)

- **Row 115** CVE-2024-34063 vodozemac — fix is a `Cargo.toml` dependency bump.
- **Row 162** CVE-2020-26297 mdBook — fix is in `searcher.js`.

(Compare comrak CVE-2021-27671, whose fix is PEG grammar. Three records in the corpus have no
Rust-level delta at all.)

## Review (11)

Rows 70, 74, 82, 195, 207, 209, 212, 215, 217, 221 + the unpatched-advisory set below. Two kinds:

- **Correct fix, bad pair** — row 74 (the `time` localtime_r fix is real but buried in a 12-file,
  451-line "v0.3 backports" release commit), rows 207, 212, 209 (broad refactors or rewrites).
- **Timing doesn't line up** — row 215 (fix predates the advisory by 536 days; verify the parent
  is really the vulnerable version).

## Twelve rows point at advisories never patched upstream

`patched = []` in advisory-db: rows 11, 50, 70, 82, 87, 195, 209, 212, 216, 217, 220, 221.
Any SHA on these rows is at best a later voluntary cleanup, not *the* fix — five are already in
the wrong-commit table. The rest (messagepack-rs, crypto2, Lucet, telemetry, arenavec, id-map,
anymap) belong in Threats to Validity: the "safe" side is a maintainer's after-the-fact rewrite,
not a released security patch.

## Metadata defects unrelated to the SHAs

- **6 duplicated CVE rows**: 72/208 (CVE-2021-32629), 84/226, 85/211, 97/210, 186/200, 205/247.
  Five pairs agree on the SHA; **186/200 disagree**, and 186 is the broken one.
- **Wrong crate labels**: row 133 says "standard library in rust" (it is matrix-sdk-crypto);
  row 168 says "futures-task crate" (it is pyo3). Both SHAs are correct.
- **Free-text crate column** — "hper crate", "hyperium/hyper", "rusqlite crate", "Wasmtime" vs
  "wasmtime". Normalise before any project-level split.
- **Still no `repo` column.** The audit workbook now carries a resolved repo per row; fold it back
  into the master sheet.

## What to do

1. Re-derive or drop the 11 wrong rows and the 4 missing SHAs before Stage 2 — a report generated
   from a version-bump commit is confidently-labelled noise.
2. Delete the five true duplicate rows and fix row 186.
3. Mark the 3 no-Rust-delta records (vodozemac, mdBook, comrak-27671) as a known limitation.
4. Carry `repo`, `rustsec_id` and `patched` into the master sheet — they make this audit
   re-runnable in one script.

*Verification pattern:* `git init && git fetch --depth=2 https://github.com/<owner>/<repo> <sha>
&& git log -1 FETCH_HEAD` — GitLab rows (sequoia ×2, buffered-reader, bam) via
`gitlab.com/api/v4/projects/<ns%2Fname>/repository/commits/<sha>`, all four verified good.

Code: `code/audit/` (step1–5 resolve crates → repos, fetch commits, compare against advisory-db; `classify.py` assigns verdicts; `table.py`/`build*.py` write the workbook).
