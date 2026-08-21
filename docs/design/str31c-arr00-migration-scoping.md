# Scoping: STR31-C's Text-Based Buffer-Size Engine vs. ARR00-C/buffer_size.rs

**Status:** Scoping complete (task 492). Migration NOT started — no rule
file has been touched by this pass. This document is the "dedicated
design/scoping pass" task 492 asked for before any migration attempt.

**Driver:** Task 492: "`src/rules/cert_c/STR/STR31-C/str31_c.rs` is a large,
fully self-contained, purely text/line-based buffer-size-resolution engine
… operating on `source.lines()` rather than the AST … a THIRD, independent,
much larger reimplementation that never adopted ARR00-C's AST-based size
resolver." Flagged by the task-481 FIO/STR audit fork as the single
biggest fix-scope item in that sweep.

---

## 1. Correction to the task's framing

The premise that STR31-C is "fully self-contained" and "never adopted"
any shared infrastructure is **half true**. Two things the task text
didn't have in front of it:

1. **STR31-C already imports and uses `src/analyze/buffer_size.rs`**
   (`eval_arith`, `memset_content_length`, `memset_content_length_in_range`,
   `ALLOC_FUNCTIONS`). That module's own header comment says it exists
   *specifically* to unify ARR30-C's and STR31-C's malloc/calloc/alloca
   arithmetic ("ARR30-C carried an AST-driven `BufferInfo`/`BufferSize`
   model … while STR31-C re-implemented overlapping malloc/calloc/alloca
   arithmetic with its own inline regex blocks"). So STR31-C has partially
   migrated before (to `buffer_size.rs`, not to ARR00-C) and then diverged
   again — several of `buffer_size.rs`'s own resolvers
   (`resolve_alloc_assigned_in_range`, `resolve_bare_alias_in_range`) go
   unused by STR31-C today even though they do almost exactly what
   STR31-C's local `find_fixed_alloc_size`/`find_alloca_size`/
   `resolve_pointer_alias_in_function` hand-roll again, slightly
   differently.

2. **`buffer_size.rs` itself is entirely text/regex-based, not AST-based.**
   It parses the raw argument *text* of an allocation call
   (`"5 * sizeof(int)"`), not an AST subtree. So "adopt buffer_size.rs" and
   "adopt an AST resolver" are two different, non-overlapping asks.

3. **ARR00-C's "AST-based size resolver" (task 234) is real, but it
   answers a narrower question than most of STR31-C's engine.**
   `resolve_declared_array_size` (`arr00_c.rs:2334`) resolves a *fixed
   array declaration's* element count from the AST: it walks C block scope
   innermost-first (`find_array_declarator_in_scope` /
   `scan_block_declarators`), evaluates the declarator's `size` field
   expression through a macro-constant table, and takes
   `max(declared_size, initializer_element_count)`. It has **no concept of
   heap allocation** (malloc/calloc/realloc/alloca), pointer aliasing,
   cross-function relay, or global-variable buffer tracking — none of
   which is in scope for ARR00-C (an OOB-access rule) but ALL of which is
   central to STR31-C (a string-copy-safety rule where the destination is
   very often a `malloc`'d buffer, a parameter, or reached through an
   alias chain).
   - It is also **rule-local**, not exposed as a shared utility —
     `arr00_c.rs` does not currently export it for STR31-C (or anyone
     else) to call.
   - `arr00_c.rs` itself still keeps a legacy text-scan fallback
     (`find_array_size`, `arr00_c.rs:2442`) for cases the AST resolver
     doesn't reach — so even ARR00-C is not "fully AST-based" today, a
     detail worth knowing before treating it as a finished exemplar to
     copy wholesale.

**Net effect on scope:** the realistic migration target is not "make
STR31-C call ARR00-C's resolver" (most of STR31-C's logic has no
counterpart there to call). It's two separate, independently schedulable
efforts:

- **(A)** Extract ARR00-C's fixed-array-declaration resolver into a shared
  `src/analyze` utility and point STR31-C's one overlapping helper
  (`find_array_declaration_size`) at it instead of its own regex scan.
- **(B)** Fold STR31-C's heap-allocation-size helpers into
  `buffer_size.rs`'s existing (but under-used) `resolve_alloc_assigned_in_range`
  family, closing the exact kind of re-divergence `buffer_size.rs` was
  built to prevent — still text-based, not a new AST capability, but a
  real de-dup with real risk-reduction (one tested implementation instead
  of two drifting ones).

Genuinely new AST capability is only needed for a handful of items (the
alias/relay/global resolution chain), and even those may not be worth an
AST rewrite — see §3.

---

## 2. Inventory: every size-resolution helper in `str31_c.rs`

| Helper | Lines (approx) | What it resolves |
|---|---|---|
| `analyze_buffer_size` | 78-122 | Dead code (`#[allow(dead_code)]`) — array-decl or malloc/calloc size, AST-based already, unused |
| `analyze_string_length` | 124-139 | String-literal length (AST node → text) |
| `get_string_length_from_context` | 141-165 | `var = "literal"` line-scan for a variable's string content |
| `get_memset_content_length` | 176-183 | Thin wrapper over `buffer_size::memset_content_length` (already shared) |
| `find_define_constant` | 185-215 | `#define NAME N` scan + usage in `var[NAME]` |
| `find_buffer_size` | 219-253 | Dispatcher: define-constant → array-decl → strlen-alloc → fixed-alloc → realloc → alloca |
| `find_array_declaration_size` | 259-315 | Fixed array declaration size via line regex (`var[N]`, `var[N*M]`) |
| `find_strlen_based_alloc_size` | 320-396 | `malloc`/`calloc(strlen(...)+1, …)` direct or via intermediate size variable |
| `line_assigns_to` | 409-414 | LHS-is-exactly-`var_name` assignment detector (word-boundary regex) |
| `find_fixed_alloc_size` | 419-468 | `malloc`/`calloc(N[*sizeof(T)])` numeric sizing, incl. parenthesized arithmetic |
| `find_realloc_dynamic_size` | 471-490 | `realloc(..., strlen(...)+...)` → treated as safe/dynamic |
| `find_alloca_size` | 493-567 | `ALLOCA`/`alloca` numeric or strlen-indirect sizing |
| `is_larger_array_variable` | 570-588 | Source-array-larger-than-dest check via line regex |
| `find_enclosing_function_lines` | 591-600 | AST-based (already) — function line-range lookup |
| `resolve_pointer_alias_in_function` / `resolve_pointer_alias_in_range` | 605-654 | One-hop `var = other;` alias resolution via line regex |
| `find_buffer_size_with_alias` | 657-695 | Orchestrates direct lookup → alias hop → global fallback → relay-source fallback |
| `find_relay_call` / `resolve_relay_source_size` | 704-784 | Cross-function "source relay" pattern (`data = badSource(data)`), same-file AST lookup + cross-file prescan fallback |
| `find_global_buffer_size` | 793-832 | Whole-file scan resolving a global's buffer size across every assignment site |
| `function_range_containing_line` | 836-841 | AST-based (already) |
| `has_prior_safe_realloc` | 844-866 | Line-order heuristic: realloc-before-copy on same var |
| `is_variable_from_getenv` / `traces_to_argv` / `is_function_parameter` | 1151-1471 | Taint-ish source classification via line-text matching |
| `check_strcpy_safety` + 5 helper fns (`extract_copy_call_args`, `check_strcpy_dest_precondition`, `check_strcpy_known_buffer_size`, `check_strcpy_source_variable_safety`, `check_strcpy_unknown_buffer_size`) | 868-1148 | strcpy-specific orchestration built on the above |
| `check_strcat_safety`, `estimate_strcat_total_length`, `check_sequential_strcat_overflow`, `extract_strcat_arguments`, `analyze_cumulative_strcat`, `get_initial_buffer_content_length`, `find_strcpy_source_length` | 1173-1296, 2040-2247 | strcat-specific orchestration + cumulative multi-strcat overflow tracking |
| `check_sprintf_safety` | 1298-1389 | Format-string-driven size estimate (`%d`/`%s`/`%c` width assumptions) |
| `check_scanf_format` | 1391-1410 | Unbounded `%s` detection (already AST-light: only needs the format string node) |
| `check_strncpy_safety` | 1807-1843 | `strncpy(dest, …, N)` where `N == sizeof(dest)` off-by-one-on-null-terminator check |
| `was_buffer_freed_in_range` | 1853-1892 | Use-after-free-into-copy check via line scan |
| `is_string_memcpy`, `is_byte_typed_buffer` | 1895-2009 | Heuristic: is this memcpy actually string-shaped |
| `check_wcstombs_safety` | 2250-2288 | Wide-to-multibyte buffer-size heuristic |
| `detect_off_by_one_error`, `loop_increments_var`, `next_statement_writes_null_at_index`, `condition_is_null_terminated_walk`, `body_has_buffer_write`, `is_relational_comparison`, `loop_has_bounds_check`, `detect_manual_string_loop`, `unwrap_parens`, `char_literal_is_null` | 1476-1804 | **Already fully AST-structural**, no line-text matching at all — these are NOT part of the fragility class the task is about |

Roughly **~1,000 of the file's 2,627 lines** are the structural (already
AST-based) off-by-one/manual-copy-loop detectors and the `CertRule`
dispatch/violation-construction boilerplate at the bottom. The genuinely
text/line-based *size-resolution* engine the task is scoped to is closer
to **~900-1,000 lines** (the size-finder family plus the strcpy/strcat/
sprintf orchestration layered on it).

---

## 3. Mapping table

| Item | Category | Notes |
|---|---|---|
| `find_array_declaration_size` | **(b) replaceable with extension** | Direct conceptual duplicate of ARR00-C's `resolve_declared_array_size`, but that function is rule-local and doesn't handle STR31-C's `#define`-constant path the way `find_define_constant` does textually — ARR00-C resolves macro constants through a proper `MacroConstantMap`, which is actually *more* correct. Extraction work: move `resolve_declared_array_size` + `find_array_declarator_in_scope` + `scan_block_declarators` + `count_initializer_elements` to a new shared module (or `buffer_size.rs`, despite its text-based framing today — needs a name/doc split, or a sibling `src/analyze/array_size.rs`), have STR31-C wire a `MacroConstantMap` the way it already receives `ProjectContext` for `callsite_param_buffer_size`, and delete `find_define_constant` + the regex half of `find_array_declaration_size`. |
| `find_fixed_alloc_size`, `find_alloca_size` (numeric-literal branches) | **(b) replaceable with extension** | `buffer_size::resolve_alloc_assigned_in_range` + `ALLOC_FUNCTIONS` already cover `malloc`/`calloc`/`realloc`/`alloca`/`ALLOCA` numeric and `N*sizeof(T)` sizing in a shared, tested function — STR31-C just isn't calling it. Extension needed: `resolve_alloc_assigned_in_range`'s regex doesn't currently handle the parenthesized-arithmetic form `malloc((N+M)*sizeof(T))` that STR31-C's `find_fixed_alloc_size`/`find_alloca_size` both hand-roll (`eval_arith` is already shared and could plug straight in once the capture groups are added). Lowest-risk of the (b) items — same text-based paradigm on both sides, just consolidating two independently-evolved regex sets into one. |
| `find_strlen_based_alloc_size`, `find_realloc_dynamic_size` (strlen/wcslen-indirect branches) | **(b) replaceable with extension** | No shared equivalent exists yet for "was this size variable itself assigned from `strlen()`/`wcslen()` earlier in the function" — `buffer_size.rs` only resolves the allocation call's own argument text, not a second-order assignment. This is the most complex of the (b) items; needs a new `resolves_to_strlen_call(var, source, fn_range)` primitive added to `buffer_size.rs` before STR31-C can drop its private copy. |
| `resolve_pointer_alias_in_range`/`resolve_pointer_alias_in_function` | **(d) partial duplicate, but already has a peer** | `buffer_size::resolve_bare_alias_in_range` is *already* an almost line-for-line match (same regex shape, same NULL/self-assignment skip logic) that STR31-C simply never adopted. Not a new capability — this is a straight swap, arguably belongs in the same low-risk (b)/dedup bucket as the alloc-size items above; listed separately only because it's a pure rename-and-delete with zero new logic needed. |
| `find_relay_call` / `resolve_relay_source_size` (cross-function "source relay" pattern) | **(c) needs new capability** | No AST or shared-utility equivalent anywhere. This is genuine interprocedural dataflow (does callee X write a size-bounded value into its own parameter before returning it), already partly modeled by `FunctionSummary::produces_param_buffer_size` for the cross-file case but hand-rolled via line regex for the same-file case. A real AST-based version would extend `FunctionSummary` to cover same-file callees uniformly instead of branching same-file-AST vs. cross-file-summary the way `resolve_relay_source_size` does today. Non-trivial; matches the task's own "needs new capability" warning. |
| `find_global_buffer_size` (whole-file scan across all assignment sites to a global) | **(c) needs new capability** | Similar shape to `global_var_null_states` in `ProjectContext` (per the capability catalog) but for buffer *size* instead of null state — no existing "global variable's joined buffer-size across all writer functions" primitive. Building one properly means walking every `function_definition` in the AST, not scanning `source.lines()` file-wide as today. |
| `is_larger_array_variable`, `get_string_length_from_context`, `get_initial_buffer_content_length`, `find_strcpy_source_length` | **(c) needs new capability (lower priority)** | All are variants of "what did this variable last look like at a given program point" — real dataflow, not a metadata lookup like ARR00-C's declarator resolver. Worth deferring behind the relay/global items above; these show up in fewer real-world FPs per the file's own comments (mostly serve Juliet-specific string-literal patterns). |
| `check_scanf_format`, `check_wcstombs_safety`, `check_sprintf_safety`'s format-width-estimate arithmetic | **(d) keep as-is** | These reason about *format-string content*, not buffer size resolution — swapping the size-lookup underneath them (once done) leaves this logic untouched. Not in scope for a size-resolver migration either way. |
| `is_variable_from_getenv`, `traces_to_argv`, `is_function_parameter` | **(d) keep as-is, but flagged as fragile independent of this task** | Pure line-text source-taint heuristics with no AST equivalent proposed here and no natural home in a "buffer size" module — they answer "where did this value come from," a different question. Worth its own future ticket if these keep causing FPs, but out of scope for task 492. |
| `detect_off_by_one_error` + support functions, `detect_manual_string_loop` + support functions | **(d) keep as-is** | Already fully AST-structural (see §2) — not part of the fragility class task 492 is about. No action needed. |
| `analyze_buffer_size` | **(d) keep as-is (dead code)** | `#[allow(dead_code)]`, unused. Should just be deleted in the same pass that touches this file, regardless of migration scope — noted as a drive-by cleanup opportunity, not fixed here per the "flag, don't quick-patch" instruction. |

---

## 4. Recommended phased plan

**Phase 1 (low risk, do first): dedup against already-shared `buffer_size.rs`.**
STR31-C's `resolve_pointer_alias_in_range`/`_in_function` and the numeric
branches of `find_fixed_alloc_size`/`find_alloca_size` have direct,
already-tested peers in `buffer_size.rs` that just aren't being called.
This is pure consolidation — same text-based paradigm, no new AST work,
lowest chance of regressing Juliet/real-world numbers. Suggested order:
swap the alias resolver first (zero behavior change expected), then the
numeric alloc-size branches (needs `resolve_alloc_assigned_in_range`
extended with the parenthesized-arithmetic capture group STR31-C already
has).

**Phase 2: extract ARR00-C's AST array-size resolver to a shared module.**
Move `resolve_declared_array_size` and its three support functions out of
`arr00_c.rs` into a new home, wire STR31-C to call it for
`find_array_declaration_size`, and — while there — replace ARR00-C's own
remaining text-scan fallback (`find_array_size`) if that's not already a
separately-tracked cleanup. This is the one item that matches the task's
literal framing ("adopt ARR00-C's AST resolver") and is the best
candidate for a focused single-PR migration once Phase 1 has established
the pattern is safe.

**Phase 3 (needs its own design pass, do not fold into this migration):
strlen-indirect alloc sizing.** Requires a new `buffer_size.rs` primitive
(`resolves_to_strlen_call`) that Phase 1's dedup doesn't need — file
separately so Phase 1/2 aren't blocked on it.

**Phase 4 (needs its own design pass — genuine new capability, largest
risk): relay-function and global-buffer resolution.** These are real
interprocedural/whole-program dataflow questions disguised as "size
resolution." Recommend treating this as its own scoping exercise against
`FunctionSummary`/`ProjectContext` rather than bolting onto the STR31-C
migration — the task's own caution ("do not attempt a quick patch") applies
most strongly here.

**Out of scope entirely for this migration:** the off-by-one/manual-loop
AST detectors (already fine), the format-string/taint-source heuristics
(different problem class), and `analyze_buffer_size` (dead code, just
delete whenever this file is next touched).

---

## 5. Suggested follow-up tasks

Not filed by this pass — listed here for the coordinator to create via
`todo-sqlite-cli add`:

1. **P2, infra** — "STR31-C Phase 1: dedup pointer-alias + fixed/alloca
   numeric sizing against `buffer_size::resolve_bare_alias_in_range` /
   `resolve_alloc_assigned_in_range`." Details: swap
   `resolve_pointer_alias_in_range`/`_in_function` for the existing
   `buffer_size::resolve_bare_alias_in_range`; extend
   `resolve_alloc_assigned_in_range`'s regex with the
   parenthesized-arithmetic capture STR31-C's `find_fixed_alloc_size`/
   `find_alloca_size` already have, then delete STR31-C's private copies.
   Juliet + real-world byte-identical is the acceptance bar (task 252/254
   precedent). Depends on: task 492 (this doc).

2. **P2, infra** — "STR31-C/ARR00-C Phase 2: extract
   `resolve_declared_array_size` (+ scope-walk helpers) from `arr00_c.rs`
   into a shared module; wire STR31-C's `find_array_declaration_size` to
   it; retire STR31-C's `find_define_constant` regex path in favor of
   ARR00-C's `MacroConstantMap`." Depends on: task 1 above (establish the
   dedup pattern first) or can run independently since it touches a
   disjoint code path.

3. **P3, infra** — "buffer_size.rs: add `resolves_to_strlen_call` primitive
   for indirect strlen/wcslen-assigned allocation sizing." Needed before
   STR31-C's `find_strlen_based_alloc_size`/`find_realloc_dynamic_size`
   strlen-indirect branches can be deduped. Standalone scoping not required
   — the shape is already fully specified by the existing STR31-C code
   this task 492 doc catalogs.

4. **P3, infra, needs its own scoping pass** — "STR31-C relay-function
   buffer-size resolution: fold same-file `find_relay_call`/
   `resolve_relay_source_size` AST lookup into `FunctionSummary` so
   same-file and cross-file relay resolution share one code path instead
   of branching AST-vs-prescan as today." Do not attempt without a
   dedicated design pass per task 492's own instruction — this is
   interprocedural dataflow, not a metadata lookup.

5. **P4, infra, needs its own scoping pass** — "STR31-C
   `find_global_buffer_size`: AST-based whole-program global-buffer-size
   join, modeled after `ProjectContext::global_var_null_states`." Lower
   priority than task 4 — narrower real-world impact (Juliet-variant-45-style
   patterns specifically, per the file's own comments).

6. **P4, infra** — "Delete `Str31C::analyze_buffer_size` (dead code,
   `#[allow(dead_code)]`, superseded by `find_buffer_size` dispatcher)."
   Trivial drive-by cleanup, no design needed; bundle into whichever of the
   above PRs touches this file first rather than filing as standalone work
   if that's simpler.

---

## 6. Latent risks/bugs observed while reading (flagged, not fixed)

- **`check_strcpy_known_buffer_size`** (`str31_c.rs:995-1007`): the "even
  smaller buffers might be okay if source is a short literal" branch
  re-checks `source_length` with `buffer_size > src_len + 1`, which is
  *stricter* than the `buffer_size > src_len` check already performed
  earlier in the same function (line ~979) for the exact same
  `(buffer_size, source_length)` pair — this second branch can now never
  fire (if the first check failed, `buffer_size <= src_len`, so
  `buffer_size > src_len + 1` is also false). Dead logic, not a
  correctness bug (no FP/FN either way), but worth removing in any pass
  that touches this function.
- **`check_strcat_safety`**'s buffer-size-known branch (`str31_c.rs:1228-1266`)
  only calls `estimate_strcat_total_length` when `buffer_size >= 20`; for
  buffers in `[1, 19]` with an unresolvable estimate it falls straight to
  "flag it," which is conservative (no FN risk) but means a legitimately
  safe small-buffer concatenation the estimator *could* have proven safe
  (e.g. `strcat(buf4, "ab")` into a 4-byte buffer with "ab" already
  accounted for) is unreachable by design. Intentional-looking (comment
  doesn't say why 20 specifically), but worth a second look if a future
  audit finds real-world FPs on small fixed buffers.
- **`find_array_declaration_size`**'s arithmetic-expression branch
  (`str31_c.rs:292-312`, `var_name[N*M]`/`[N+M]`/`[N-M]`) only matches a
  *two-numeric-literal* expression — `var[SIZE*2]` (one literal, one
  macro) falls through to `find_define_constant`'s much weaker "does this
  line contain both the var name and some `#define`'d name" check, which
  has no operator-awareness at all and will happily match unrelated
  `#define`s that merely co-occur on the same line as `var_name` and a
  `[`/`]`. This is a real false-size risk (wrong constant substituted) that
  the ARR00-C extraction in Phase 2 would fix as a side effect (its
  `MacroConstantMap` + real AST size-expression evaluator handles mixed
  literal/macro arithmetic correctly) — one more argument for prioritizing
  Phase 2 rather than leaving it as a "nice to have."
- **`resolve_relay_source_size`**'s alias-hop fallback
  (`str31_c.rs:766-774`) resolves at most one additional alias hop inside
  the relay function; a relay that goes `char *buf = malloc(...); char
  *buf2 = buf; data = buf2;` (two hops) silently returns `None` and the
  caller falls through to "unresolvable," which is conservative (stays a
  finding) rather than a false-negative risk — flagged only because it's
  the kind of arbitrary depth limit that tends to need bumping once a
  real-world oracle exercises it.
