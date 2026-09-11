# HaluRust — Sample Extraction Spec & Batch Progress (Aug 14–19 2026)

Companion to `07_halurust_v2_roadmap.md`. Operating spec for turning
`Gurman_Halurust_Combined_Dataset_Till_Date.xlsx` rows into vulnerable/safe Rust sample pairs.

**STATUS: COMPLETE.** Rows 200–232 (33 records) → **32 verified `.rs` pairs + 1 record that has
no Rust pair** (comrak CVE-2021-27671, grammar-only fix — see Batch 7).

---

## Locked spec (Gurman's wording, Aug 14 2026)

1. Find the commit that modifies actual `.rs` source — **not** merge commits, **not** changelog-only commits.
   If a merge commit only touches markdown/toml, drill into the PR commits to find the real fix.
2. Fetch the diff, extract function-level code.
3. Per CVE, emit **exactly two files with identical names**: `CVE-<YEAR>-<ID>_CWE-<CWE-ID>.rs`
   - First file presented = **vulnerable** (parent commit)
   - Second file presented = **safe** (fix commit)
4. **No labels, suffixes, or prefixes in filenames** — no `_vulnerable`, `_safe`, `_fixed`.
5. **No added comments inside the code** — no `// VULNERABLE VERSION` etc. Original repo comments stay.
6. Raw code only, exactly as it appears in the repository.
7. State in plain text which file is vulnerable and which is safe. Vulnerable always first.
8. Work in **batches of 5**, in sheet order; pause for go-ahead between batches.

## Scope convention applied

Extract every **non-test** function whose body a patch hunk touches, plus new helper functions the
fix introduces (these appear only in the safe file). Hunks in `tests/`, `benches/`, `examples/`,
docs and changelogs are excluded. Where a fix spans several files, extraction targets the file
containing the semantic fix. Where a fix sprawls across many functions, pick the one carrying the
vulnerability semantics. Where the fix itself is only a line or two (trait bounds, a type change),
pull in the enclosing type and its impls so the sample is usable rather than a fragment.

## Working method

- `raw.githubusercontent.com` serves byte-exact file contents at any commit SHA.
- `crates.io/api/v1/crates/<name>` resolves the `repository` field. When that field
  is `null` (nano_arena), fall back to the RustSec advisory TOML at
  `raw.githubusercontent.com/rustsec/advisory-db/main/crates/<crate>/RUSTSEC-YYYY-NNNN.md` — its
  `url =` points at the upstream repo/issue and `aliases` cross-references the CVE.
- Ask for *every* changed file, not just `.rs` — otherwise a grammar-only or config-only fix looks
  like an empty commit.
- `.patch` URLs are unreliable for large diffs — fetch whole files at both commits and diff locally.
- Brace-matched extraction by item name (or regex for impl blocks); **verify every output line is a
  verbatim substring of its source file** before delivering.
- For names with many occurrences in one file (macro-generated impls), select the occurrence whose
  extracted body contains a marker string from the diff rather than guessing an index.
- Cheap repo+SHA check:
  `curl -o /dev/null -w '%{http_code}' https://raw.githubusercontent.com/<owner>/<repo>/<sha>/Cargo.toml`

## Known data gap

Column E is `Reference Commit` — a bare 40-char SHA with **no repository URL**.
**Add a `repo` column to the sheet.** *(Now carried in `data/halurust_metadata.csv`.)*
Resolution table for rows 200–232:

| Crate | Repo |
|---|---|
| hyper | hyperium/hyper |
| ammonia | rust-ammonia/ammonia |
| prost-types | tokio-rs/prost |
| tokio | tokio-rs/tokio |
| grep-cli (ripgrep) | BurntSushi/ripgrep |
| nalgebra | dimforge/nalgebra |
| lettre | lettre/lettre |
| iced-x86 | icedland/iced (Rust under `src/rust/iced-x86/`) |
| cranelift-codegen | bytecodealliance/wasmtime |
| anymap | chris-morgan/anymap |
| comrak | kivikakk/comrak |
| rkyv | rkyv/rkyv |
| id-map | andrewhickman/id-map |
| outer_cgi | SolraBizna/outer_cgi |
| reorder | tiby312/reorder |
| stackvector | Alexhuszagh/rust-stackvector |
| slice-deque | gnzlbg/slice_deque (underscore, not hyphen) |
| telemetry | Yoric/telemetry.rs |
| rocket | SergioBenitez/Rocket |
| uu_od | uutils/coreutils |
| parse_duration | zeta12ti/parse_duration |
| arenavec | ibabushkin/arenavec |
| fltk | fltk-rs/fltk-rs |
| internment | droundy/internment |
| quinn | quinn-rs/quinn |
| stack_dst | thepowersgang/stack_dst-rs |
| byte_struct | wwylele/byte-struct-rs |
| nano_arena | bennetthardwick/nano-arena (crates.io `repository` null — via RUSTSEC-2021-0031) |
| scratchpad | okready/scratchpad |
| truetype | bodoni/truetype |
| toodee | antonmarsden/toodee |
| rand_core | rust-random/rand |

Rows 197–199 are blank.

---

## Progress — all 7 batches delivered

| Batch | Rows | CVEs | Status |
|---|---|---|---|
| 1 | 200–204 | CVE-2021-32715, 38193, 38192, 38191, 3013 | ✅ |
| 2 | 205–209 | CVE-2021-38190, 38189, 38188, 32629, 38187 | ✅ |
| 3 | 210–214 | CVE-2021-38186, 31919, 30455, 30454, 29941 | ✅ |
| 4 | 215–219 | CVE-2021-29939, 29938, 29937, 29935, 29934 | ✅ |
| 5 | 220–224 | CVE-2021-29932, 29930, 28306, 28037, 28036 | ✅ |
| 6 | 225–229 | CVE-2021-28034, 28033, 28032, 28031, 28030 | ✅ |
| 7 | 230–232 | CVE-2021-28028, 27671 ⚠, 27378 | ✅ (27671 has no Rust pair) |

### Batch 1

| CVE | CWE | Crate | Parent → Fix | Extracted |
|---|---|---|---|---|
| CVE-2021-32715 | CWE-444 | hyper | 1068b994 → 1fb719e0 | `content_length_parse`, `content_length_parse_all_values` (+`from_digits` safe) — `src/headers.rs` |
| CVE-2021-38193 | CWE-79 | ammonia | ae3fb569 → 4b8426b8 | `clean_dom` (+`check_expected_namespace` safe) — `src/lib.rs` |
| CVE-2021-38192 | CWE-120 | prost-types | 0833d467 → 59f2a731 | `Duration::normalize`, `Timestamp::normalize` — `prost-types/src/lib.rs` |
| CVE-2021-38191 | CWE-362 | tokio | a5ee2f0d → e3851089 | `JoinHandle::abort` — `tokio/src/runtime/task/join.rs` |
| CVE-2021-3013 | CWE-78 | grep-cli (ripgrep) | 8ec6ef37 → 229d1a8d | `associate`, `default_decompression_commands` (+`try_associate`, `resolve_binary` safe) — `crates/cli/src/decompress.rs` |

### Batch 2

| CVE | CWE | Crate | Parent → Fix | Extracted |
|---|---|---|---|---|
| CVE-2021-38190 | CWE-119 | nalgebra | 58bea21d → 5bff5368 | `struct VecStorage` (+ manual `Serialize`/`Deserialize` safe) — `src/base/vec_storage.rs` |
| CVE-2021-38189 | CWE-77 | lettre | d930c42d → 8bfc2050 | `ClientCodec::encode` — `lettre/src/smtp/client/mod.rs` |
| CVE-2021-38188 | CWE-131 | iced-x86 | 8209aa94 → 3c607a00 | `get_constant_offsets` — `src/rust/iced-x86/src/decoder.rs` |
| CVE-2021-32629 | CWE-788 | cranelift-codegen | 0f5bdc64 → 95559c01 | `gen_load_stack` — `cranelift/codegen/src/isa/x64/abi.rs` |
| CVE-2021-38187 | CWE-681 | anymap | 9ddafe25 → 93511917 | `trait UncheckedAnyExt`→`trait Downcast` + `extend` — `src/any.rs`, `src/lib.rs` |

### Batch 3

| CVE | CWE | Crate | Parent → Fix | Extracted |
|---|---|---|---|---|
| CVE-2021-38186 | CWE-79 | comrak | 6d6b7728 → b72340ca | `escape_href` — `src/html.rs` |
| CVE-2021-31919 | CWE-909 | rkyv | f141b560 → 9c65ae9c | `resolve_aligned`, `resolve_unsized_aligned` — `rkyv/src/ser/serializers/std.rs` |
| CVE-2021-30455 | CWE-415 | id-map | a2fa8d4a → fab6922b | `drop_values` + `impl Drop` + `impl Clone` (vuln only) — `src/lib.rs` |
| CVE-2021-30454 | CWE-119 | outer_cgi | 6e87e8b3 → 439d239c | `read_length` — `src/fcgi.rs` |
| CVE-2021-29941 | CWE-787 | reorder | 5a7aa092 → 8b0eba0b | `reorder_index` — `src/lib.rs` |

### Batch 4

| CVE | CWE | Crate | Parent → Fix | Extracted |
|---|---|---|---|---|
| CVE-2021-29939 | CWE-787 | stackvector | eb759f9e → 50061090 | `insert_many` — `src/lib.rs` |
| CVE-2021-29938 | CWE-415 | slice-deque | 15eb11c5 → 1c8edcbe | `tail_head_slice` — `src/lib.rs` |
| CVE-2021-29937 | CWE-908 | telemetry | 5c810a83 → 2820cf12 | `vec_resize` (vuln only) + `vec_with_size` — `src/misc.rs` |
| CVE-2021-29935 | CWE-416 | rocket | b4fadae5 → b53a906a | `with_prefix` — `core/http/src/uri/formatter.rs` |
| CVE-2021-29934 | CWE-125 | uu_od | e2b58051 → 39d62c6c | `PartialReader::read` — `src/uu/od/src/partialreader.rs` |

### Batch 5

| CVE | CWE | Crate | Parent → Fix | Extracted |
|---|---|---|---|---|
| CVE-2021-29932 | CWE-770 | parse_duration | 13cc9dd2 → 75bcb2b4 | `parse` — `src/parse.rs` |
| CVE-2021-29930 | CWE-787 | arenavec | 9a3579be → 286c8e30 | `resize`, `clear` — `src/common.rs` |
| CVE-2021-28306 | CWE-476 | fltk | bbace849 → fdfa8eb3 | `handle`, `handle_main` — `fltk/src/app.rs` |
| CVE-2021-28037 | CWE-362 | internment | 863dbc06 → 2928a87a | `struct Intern` + `Clone`/`Copy`/`Send`/`Sync` impls — `src/lib.rs` |
| CVE-2021-28036 | CWE-119 | quinn | f3d82d79 → 29d37aa6 | `send` ×2 (cfg variants), `prepare_msg` — `quinn/src/platform/unix.rs` |

### Batch 6

| CVE | CWE | Crate | Parent → Fix | Extracted |
|---|---|---|---|---|
| CVE-2021-28034 | CWE-415 | stack_dst | 807e9d45 → 2a4d5380 | `push_inner`, `push_cloned` — `src/stack.rs` |
| CVE-2021-28033 | CWE-908 | byte_struct | 9c41996e → a5356783 | `read_bytes_default_le/be` (macro-generated array impl, 15th occurrence) — `byte_struct/src/lib.rs` |
| CVE-2021-28032 | CWE-416 | nano_arena | f5306c73 → 6b83f9d0 | `Arena::split_at` — `src/lib.rs` |
| CVE-2021-28031 | CWE-415 | scratchpad | 0cc776fb → 18abedad | `move_elements` ×2 — `src/traits.rs` |
| CVE-2021-28030 | CWE-908 | truetype | cb65bc79 → 1f2dc7f3 | `take_bytes` — `src/tape.rs` |

### Batch 7 (final)

| CVE | CWE | Crate | Parent → Fix | Extracted |
|---|---|---|---|---|
| CVE-2021-28028 | CWE-415 | toodee | 676fe64f → ced70c17 | `insert_row`, `insert_col` — `src/toodee.rs` |
| CVE-2021-27671 | CWE-79 | comrak | 56eabe0c → b3efbb6e | ⚠ **no Rust pair — see below** |
| CVE-2021-27378 | CWE-131 | rand_core | 6ecbe262 → 390a7b10 | `read_u32_into`, `read_u64_into` — `rand_core/src/le.rs` |

**⚠ CVE-2021-27671 (comrak) has no vulnerable/safe Rust function pair.**

The fix commit `b3efbb6e` ("SECURITY: match unsafe prefixes case-insensitively") changes exactly two
files: `src/lexer.pest` and `src/tests.rs`. Verified byte-for-byte that `src/html.rs` and
`src/parser/autolink.rs` are **identical** at parent and fix. The entire fix is one line of PEG grammar:

```
- dangerous_url = { "data:" ~ !("image/" ~ ("png" | "gif" | "jpeg" | "webp")) | "javascript:" | "vbscript:" | "file:" }
+ dangerous_url = { ^"data:" ~ !(^"image/" ~ (^"png" | ^"gif" | ^"jpeg" | ^"webp")) | ^"javascript:" | ^"vbscript:" | ^"file:" }
```

`^` is pest's case-insensitive operator, so `JavaScript:` bypassed the filter. Delivered as
`CVE-2021-27671_CWE-79.pest` (both sides, verbatim) rather than fabricating a `.rs` pair.

**Do not** substitute the Rust function that consumes `dangerous_url` — it is byte-identical on both
sides, so the "pair" would have zero delta and would train the model on a false example.

**Other Batch 7 notes:**

- **rand_core** is the highest-value minimal pair in the corpus: `assert!(4 * src.len() >= dst.len())`
  → `assert!(src.len() >= 4 * dst.len())`. The operands are transposed — the vulnerable assertion is
  *present and looks correct at a glance* but is off by a factor of 16. Same for the u64 variant.
  17 lines on both sides, identical length. If a detector catches this one it is genuinely reading
  the arithmetic.
- **toodee** `insert_row`/`insert_col` called `set_len` before writing, so a panic in `iter.next()`
  dropped uninitialized/duplicated elements. Fix sets `len` to `start` first, caps with `.take()`,
  and asserts the iterator length — `ExactSizeIterator::len()` is not trustworthy in unsafe code.

---

## Final corpus statistics for this batch (32 `.rs` pairs, 64 samples)

```
safe longer than vulnerable : 18
safe shorter                :  6
identical length            :  8
mean   vulnerable 44.8 L    safe 58.0 L
median vulnerable 34   L    safe 40   L
ratio range  0.13× (id-map)  …  5.56× (nalgebra)
```

**LENGTH-ONLY BASELINE: 59.4%** on this batch (0.805 pairwise on the full audited corpus). A
classifier that sees only line count uses no security information at all. **Report this as an
explicit floor in the results table.**

Structural shapes driving the leakage:

1. **Derive-level vulns** (nalgebra) — no vulnerable function body exists.
2. **Deletion fixes** (id-map, telemetry, byte_struct) — safe side is a fraction of the size.
3. **Formatting churn inside the fix commit** (reorder) — rustfmt ran alongside the fix.
4. **Macro-generated code** (byte_struct) — the sample is a macro body, not an ordinary fn.
5. **Signature changes** (fltk) — the fix alters the function's type, not just its body.
6. **Non-Rust fixes** (comrak 27671) — no pair exists at all.

## Samples worth inspecting individually in the results

- **rand_core CVE-2021-27378** — transposed operands in an assertion that looks correct.
- **nano_arena CVE-2021-28032** — bug is misplaced trust in a `Borrow` impl; nothing looks wrong locally.
- **rocket CVE-2021-29935** — the unsound `transmute` is present in *both* versions; only panic-safety differs.
  Defeats any "contains unsafe" heuristic in both directions.
