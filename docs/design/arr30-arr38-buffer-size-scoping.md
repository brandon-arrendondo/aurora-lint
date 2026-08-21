# Scoping: ARR30-C's and ARR38-C's Buffer-Size/Declaration Subsystems

**Status:** Scoping complete (task 497). Migration NOT started — no rule
file has been touched by this pass. This document is the "dedicated
fix-scoping pass" task 497 asked for before any migration attempt.

**Driver:** Task 497: ARR30-C (~6650 lines, ~150 helpers) and ARR38-C
(~3200 lines, ~90 helpers) are two more independent buffer-size-resolution
subsystems, flagged by task 481's final deep-dive fork as "hiding
substantially more, not clean" even after a partial read. This is now the
3rd/4th independent buffer-size-resolution reimplementation found in the
ruleset (STR31-C already scoped in task 492/
`docs/design/str31c-arr00-migration-scoping.md`; ARR30-C and ARR38-C here;
MEM05-C flagged separately under task 481).

**Coverage caveat (read before trusting completeness claims below):**
ARR30-C's ~150 functions and ARR38-C's ~90 were **not** all read
line-by-line. This pass read ARR30-C's module doc, `check()` entry point,
the full `extract_buffer_from_*`/`parse_malloc_arguments` declaration/
allocation-parsing family (~700 lines, arguably the file's most
load-bearing buffer-size logic), and grep-sampled the remaining ~130
function signatures for name collisions against shared-layer primitives.
ARR38-C was read more completely (its `find_array_size`/
`find_string_literal_length`/`try_parse_size`/alias-collection helpers,
~400 lines) plus the same signature sweep for the rest. Large stretches of
both files (ARR30-C's VRA/CFG-integrated bounds-checking logic, ~2000
lines around `check_for_loop_bounds_against_size`/
`check_unbounded_decode_loop`/`check_param_decode_overread`; ARR38-C's
per-library-function checkers `check_memory_function`/
`check_string_function`/etc., ~1500 lines) were **not** read at all in
this pass — they're bounds-*checking* logic layered on top of the
size-*resolution* primitives this task is scoped to, and are a
plausible source of the "hiding substantially more" the task text warns
about, but confirming that needs its own read, not claimed here.

---

## 1. ARR30-C: mostly AST-based already, with real self-duplication

Unlike STR31-C (which is fundamentally `source.lines()`-based) or ARR38-C
(below), ARR30-C's declaration/allocation-parsing family
(`extract_buffer_from_declaration[_with_typedefs]`,
`extract_buffer_from_init_declarator[_with_typedefs]`,
`extract_buffer_from_array_declarator`, `extract_multidimensional_buffers`,
`extract_inner_dimensions`, `extract_buffer_from_malloc_call`,
`parse_malloc_arguments`) is **already AST-based**, walks `tree_sitter::Node`
children directly, and already calls into `buffer_size::calculate_malloc_size`
/ `calculate_alloc_bytes` / `extract_numeric_value` / `extract_sizeof_value`
/ `evaluate_simple_arithmetic` for the numeric-resolution leaf work. The
multidimensional-array handling (`extract_buffer_from_array_declarator`'s
recursion into the innermost `array_declarator`, `extract_inner_dimensions`'
`"{base}[*]"` wildcard-entry convention for outer dimensions) reads as
correct for the 2D/3D cases it's designed for — no bug found in the sampled
read, though 4+-dimensional arrays and mixed array-of-pointers-to-arrays
shapes weren't specifically stress-tested here.

**The real finding is that ARR30-C duplicates itself, not just external
shared primitives:**

1. **`Self::find_identifier_in_declarator`** (line 5756) is a rule-local
   method that is **byte-for-byte identical in logic** to the free function
   `crate::utility::cert_c::ast_utils::find_identifier_in_declarator`,
   which ARR30-C **already imports** (line 58) and correctly uses elsewhere
   in the same file (e.g. `extract_buffer_from_array_declarator`'s
   `function_declarator | pointer_declarator | parenthesized_declarator`
   arm, line 5575). The self-method is called once, from
   `extract_buffer_from_malloc_call` (line 5716). This is the exact
   "shadowing an already-imported shared primitive with a rule-local
   re-implementation" pattern task 481's sweep was built around — just
   caught here *within* a single file instead of across files.

2. **`extract_variable_name_from_declarator`** (line 4607) is a second,
   narrower reimplementation of the same "unwrap a declarator to its
   identifier" concept: it only handles `identifier` and
   `pointer_declarator` (recursing into the latter), returning `None` for
   anything else. It has exactly one call site
   (`extract_assignment_lhs`, line 4587, itself only reached from
   `find_malloc_assignments`'s declaration-with-initializer arm), so its
   narrower coverage is unlikely to matter in practice for its actual
   call site (an `array_declarator` or `function_declarator` LHS of a
   direct `malloc`/`calloc`/`realloc` assignment is not realistic C), but
   it's still a third local copy of a concept the file already has two
   better answers for (the imported `find_identifier_in_declarator` and
   `ast_utils::get_identifier_from_declarator`, also imported line 59 but
   apparently unused by this specific call chain).

**Net effect on scope:** ARR30-C's core buffer-size *resolution* logic does
not need an ARR00-C-style AST-resolver migration — it already has one, and
it's reasonably solid. What it needs is a same-file dedup: delete both
rule-local identifier-unwrap methods and route their one and two call
sites through the already-imported `ast_utils::find_identifier_in_declarator`
(or `get_identifier_from_declarator` if the narrower one's specific
call site actually wants array/function-declarator coverage too — worth
checking when this lands, since it's a one-line behavior broadening at
worst, and the current narrow behavior for that call site was never
observed to cause a problem).

---

## 2. ARR38-C: fully text-based, its own independent size-parsing stack

ARR38-C's size/declaration helpers operate on pre-extracted `&str` snippets
(argument text, declaration text), not AST nodes — a different paradigm
from ARR30-C entirely, closer to STR31-C's. Confirmed duplication against
the shared layer:

| Item | Category | Notes |
|---|---|---|
| `find_array_size`, `find_string_literal_length` | **(d) fixed, keep as-is** | Task 496's fix has already landed: both callers (`is_short_string_source`) pass `scoped_source` derived from `find_containing_function(node)` before calling either helper (line 2503), so the "whole-file unscoped search" risk task 496 flagged is closed. No further action needed here. |
| `try_parse_size`, `extract_elem_count_from_byte_expr` | **(b) replaceable with extension** | Independent reimplementation of `buffer_size::calculate_malloc_size`'s `N*sizeof(T)` / `sizeof(T)*N` pattern (buffer_size.rs only tries `COUNT * sizeof(TYPE)` in that left-to-right order; ARR38-C's version also tries the reverse `sizeof(TYPE) * COUNT` order that buffer_size.rs does not). Needs `calculate_malloc_size` extended with the reversed-order case before ARR38-C can drop its copy — a small, additive change (same shape as task 509's nested-multiply fix for STR31-C). |
| `sizeof_type` | **(c) needs reconciliation, not just dedup** | ARR38-C has its **own third** `type_name -> byte_size` table, distinct from both `buffer_size::extract_sizeof_value`'s and `size_analysis.rs`'s (per the capability catalog, `size_analysis.rs` is a separate legacy file with likely a fourth). ARR38-C's table also contains a Juliet-specific hack — `"twoIntsStruct" => Some(8)` — hardcoded for one Juliet test struct name, which has no place in a genuinely shared primitive. Consolidating four divergent type-size tables into one canonical `sizeof_type_bytes(&str) -> Option<usize>` in `buffer_size.rs` is worth doing on its own before any rule migrates onto it, and the Juliet-specific entry should NOT be carried into the shared version (flag it as a rule-local Juliet accommodation if still needed, not a real "sizeof" answer). |
| `collect_pointer_aliases` | **(d) keep as-is, note for future unification** | AST-scoped (`query::find_descendants_of_kind(node, "expression_statement")`, so already function/range-scoped by its caller) rather than STR31-C's raw regex-over-lines. Returns *all* simple-identifier-to-simple-identifier aliases in a `Vec`, a different shape than `buffer_size::resolve_bare_alias_in_range`'s "first hit for one specific variable" — not a strict duplicate, but conceptually the same "bare alias" question answered a third way (STR31-C's regex scan, `buffer_size.rs`'s shared single-lookup, this AST-scoped batch collector). Worth a future "which shape does buffer_size.rs actually want to export" design question, not an immediate fix. |
| `extract_array_var_name`, `extract_array_size` (both `&str`-based, ARR38-C lines 2780/2798) | **(d) keep as-is, naming-trap risk only** | Confirms and extends the "extract_array_size naming trap" task 481 already flagged (ARR02-C's AST-`Node` version vs. ARR38-C's text version) — ARR30-C *also* has its own `extract_array_size(&self, node: &Node, source: &str) -> Option<BufferSize>` (line 5689), a third same-named function with yet another signature/return type. Not a behavioral bug (each is only called within its own file), but a real maintainer trap: renaming one during a future refactor without checking the others risks a silent wrong-function call if any of these are ever made `pub`/shared under the same name. Worth a drive-by rename if any of the three is touched for other reasons; not worth a dedicated task on its own. |
| `is_alloc_call` (ARR30-C, line 4519) | **(b) already tracked** | Not new — this is exactly task 498 ("Migrate ARR30-C's is_alloc_call to call_roles::is_allocator_call once task 497's dedicated audit lands"), already filed and now unblocked. One nuance worth carrying into that task: `call_roles::is_allocator_call` covers malloc/calloc/realloc/aligned_alloc/strdup/strndup, but ARR30-C's `is_alloc_call` (malloc/calloc/realloc only) feeds a NULL-pointer-arithmetic check specifically — `alloca` is correctly excluded there (it can't return NULL the way heap allocators can), so migrating to `is_allocator_call` should keep excluding `alloca`/`_alloca`/`ALLOCA`, which `is_allocator_call` already does (it has no alloca in its list) — no conflict, just worth confirming during that task rather than assuming a blind swap. |

---

## 3. Recommended phased plan

**Phase 1 (near-zero risk, do first): ARR30-C self-dedup.** Delete
`Self::find_identifier_in_declarator` (line 5756) and its one call site's
`self.find_identifier_in_declarator(...)` invocation in
`extract_buffer_from_malloc_call`, replacing it with the already-imported
free function `find_identifier_in_declarator` (no `self.` prefix — it's a
free function import, not a method). Logic is byte-identical, so this
should be Juliet/real-world byte-identical by construction; still worth
running the full protocol per CLAUDE.md since it's a live detection file.
Optionally fold in `extract_variable_name_from_declarator`'s single call
site at the same time (swap for the imported `find_identifier_in_declarator`
too, which is a strict coverage superset) — same risk profile.

**Phase 2: ARR38-C `try_parse_size`/`extract_elem_count_from_byte_expr`
dedup against `buffer_size::calculate_malloc_size`.** Requires extending
`calculate_malloc_size` with the reversed `sizeof(T)*N` order first (small,
additive — mirrors task 509's already-planned nested-multiply extension
for the same function). Do this alongside or after task 509 rather than as
a third independent edit to the same function.

**Phase 3: consolidate the sizeof-type-size tables.** At least three
(`buffer_size::extract_sizeof_value`, ARR38-C's `sizeof_type`, and
whatever `size_analysis.rs` has — not confirmed read in this pass) disagree
on coverage and byte widths for the same concept. Worth a small dedicated
task since it's a pure "one canonical table" consolidation, not
detection-logic-changing on its own, but touches enough call sites
(ARR30-C, ARR38-C, `size_analysis.rs` consumers) to warrant its own
Juliet/real-world validation pass rather than folding into Phase 2.

**Phase 4 (needs its own scoping, not attempted here): the ~2000 unread
lines of ARR30-C's VRA/CFG bounds-checking logic and ~1500 unread lines of
ARR38-C's per-library checkers.** This pass did not read them and cannot
rule out further duplication or bugs there — task 481's "hiding
substantially more, not clean" assessment may still apply to those
sections specifically. If a future session wants full confidence these
two files are clean, that's the remaining gap, not anything itemized
above.

**Out of scope / already resolved:** ARR38-C's `find_array_size`/
`find_string_literal_length` scoping (task 496, confirmed fixed);
ARR30-C's `is_alloc_call` migration (task 498, already filed, now
unblocked by this doc).

---

## 4. Suggested follow-up tasks

Not filed by this pass — listed here for the coordinator to create via
`todo-sqlite-cli add`:

1. **P2, infra** — "ARR30-C: delete self-duplicated
   `find_identifier_in_declarator`/`extract_variable_name_from_declarator`,
   route through the already-imported `ast_utils::find_identifier_in_declarator`."
   Details: `find_identifier_in_declarator` (arr30_c.rs:5756) is a
   byte-identical rule-local copy of the free function already imported at
   line 58 and used elsewhere in the same file (line 5575) — delete the
   method, replace its one call site in `extract_buffer_from_malloc_call`
   (line 5716) with the free function. `extract_variable_name_from_declarator`
   (line 4607) is a second, narrower copy of the same concept with one call
   site (`extract_assignment_lhs`, line 4587) — same treatment. Acceptance
   bar: Juliet + real-world byte-identical (expected by construction, same
   logic). See `docs/design/arr30-arr38-buffer-size-scoping.md` section 1.
   Depends on: task 497 (this doc).

2. **P3, infra** — "buffer_size.rs: extend `calculate_malloc_size` with
   reversed `sizeof(T)*N` order; dedup ARR38-C's `try_parse_size`/
   `extract_elem_count_from_byte_expr` onto it." Bundle with or sequence
   after task 509 (STR31-C's nested-multiply extension to the same
   function) rather than editing `calculate_malloc_size` a third time
   independently. See section 2 above.

3. **P3, infra** — "Consolidate the 3+ divergent sizeof-type-size tables
   (`buffer_size::extract_sizeof_value`, ARR38-C's `sizeof_type`,
   `size_analysis.rs`'s equivalent if any) into one canonical function in
   `buffer_size.rs`." Drop ARR38-C's Juliet-specific `"twoIntsStruct" => 8`
   entry rather than carrying it into the shared version — flag it as a
   rule-local Juliet accommodation only if still needed after
   consolidation. See section 2 above.

4. **P4, infra, needs its own scoping pass** — "ARR30-C's ~2000-line
   VRA/CFG-integrated bounds-checking logic and ARR38-C's ~1500-line
   per-library-function checkers: unread by task 497's scoping pass, may
   still be 'hiding substantially more' per task 481's original
   assessment." Not confirmed to contain issues — this is an honest gap
   flag, not a known-bug task. See section 3 (Phase 4) above.

5. **No task needed** — the "extract_array_size naming trap" (ARR00-C,
   ARR30-C, ARR38-C all define a same-named function with different
   signatures) is noted for awareness only; fold a rename into whichever
   of the three is next touched for unrelated reasons rather than filing
   standalone busywork.

---

## 5. Latent risks/bugs observed while reading (flagged, not fixed)

- **ARR30-C `find_identifier_in_declarator` self-duplication** (line
  5756) — see section 1. Not a correctness bug (same logic as the
  imported version), but a real maintenance hazard: a future fix to
  `ast_utils::find_identifier_in_declarator` (e.g. adding a new
  declarator-kind case) would silently NOT apply to this file's one call
  site, since it calls the shadowing local copy instead.
- **ARR38-C `sizeof_type`'s `"twoIntsStruct" => Some(8)`** (line 2751) —
  a benchmark-specific hack baked into what reads as a general-purpose
  helper. Not incorrect for its narrow purpose (a fixed Juliet CWE-121/122
  test struct really is 8 bytes), but it's a maintainability smell: a
  real-world codebase with an unrelated `twoIntsStruct` type of a
  different size would get a silently wrong `sizeof_type` answer. Flagged
  for removal if/when this table is consolidated (Phase 3 above), not
  fixed here.
- **ARR30-C's `extract_buffer_from_array_declarator`/
  `extract_inner_dimensions` multidimensional handling** — reads correct
  for 2D/3D arrays in the sampled read (recursion into the innermost
  `array_declarator`, `"{base}[*]"` wildcard convention for outer
  dimensions), but was not stress-tested against 4+-dimensional arrays or
  arrays-of-pointers-to-arrays shapes in this pass. Not a confirmed bug —
  flagged as an area a future full read should specifically exercise
  given the file's own comment trail shows this logic has been touched
  for edge cases before (task 235's `field_identifier` fix, cited inline
  at line 5524).
- **`extract_variable_name_from_declarator`'s narrow coverage** (line
  4607, only `identifier`/`pointer_declarator`) — not observed to cause a
  false negative given its one call site's context (malloc/calloc/realloc
  assignment LHS is realistically always one of those two shapes), but
  flagged in case a future edit reuses this function for a broader
  purpose without noticing its narrower-than-`ast_utils` coverage.
