# Scoping: ARR30-C's and ARR38-C's Buffer-Size/Declaration Subsystems

**Status:** Scoping complete for both the size-resolution layer (task 497)
and the bounds-checking layer (task 512, sections 6-8 below). Migration/fix
work NOT started — no rule file has been touched by either pass. This
document is the "dedicated fix-scoping pass" task 497 asked for before any
migration attempt, extended by task 512 to cover the layer task 497
explicitly left unread.

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

**Update (task 512):** that remaining layer has now been read — see
sections 6-8 below. It turned up a real false-negative bug class in
ARR30-C's older regex-heuristic layer (missing word-boundary anchors) and
confirmed the same unscoped-whole-file-search bug class task 496 fixed
elsewhere in ARR38-C is still present in two functions this pass hadn't
reached. Task 481's "hiding substantially more" assessment was directionally
right.

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

**Phase 4 (done — task 512): the ~2000 unread lines of ARR30-C's VRA/CFG
bounds-checking logic and ~1500 unread lines of ARR38-C's per-library
checkers.** Read in full; see sections 6-8 below for findings. Confirms
task 481's "hiding substantially more, not clean" assessment — both files
have live false-negative bugs in this layer, not just duplication.

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

---

## 6. ARR30-C bounds-checking layer (task 512)

**Scope actually read vs. sampled:** the ~2000-line estimate undercounted
the real boundary. This pass traced the bounds-*checking* family from
`has_dynamic_bounds_check`/`is_static_function` (line 1481) through
`check_overread_helper_callsite`/`is_alloc_call` (line 4577) — roughly
**2,900 lines** — plus spot checks of `has_lower_bound_check` (5144) and
`get_array_name_from_subscript`/`get_subscript_index_value` (993-1082)
that feed the same violation path. Read essentially in full, with one
exception: the "mod-roundup" arithmetic-proof family (lines 2530-3010,
~15 functions, heavily task-cited: 446/448) was read for structure/
soundness but not hand-verified derivation-by-derivation — it reads as
internally consistent. Lines 5091-5166/6710+ beyond the two functions
spot-checked were not read.

### 6.1 A legacy regex-heuristic layer with real false-negative bugs sits underneath newer, well-engineered VRA/AST logic

The newer additions to this file (VRA suppression at
`is_fixed_size_variable_index_violation`/3081, the blob-taint decode-loop
detector at `check_unbounded_decode_loop`/3773, the interprocedural
over-read summary at `check_overread_helper_callsite`/4412, the round-up-
allocation soundness proof at `index_is_bounded_by_alloc_roundup`/2530)
are genuinely careful: AST-node-based, explicit comment/string
sanitization via `text_sans_comments_and_strings`, word-bounded regexes
(`\b`), thorough doc-comment soundness arguments citing specific tasks
(172, 206, 210, 211, 434, 436, 443, 446, 448).

But three functions that gate the *same* violation decisions are much
older-style and share a real bug: **regex patterns built directly from
`regex::escape(param_name)` with no `\b` word-boundary anchors, run over
raw (non-comment-stripped) function text**:

- **`has_function_parameter_bounds_check`** (1562-1605) — used by both
  `is_fixed_size_variable_index_violation` (3142) and
  `check_unvalidated_param_index` (2482) to decide whether a
  parameter-indexed access is "checked." A pattern like
  `format!(r"{}\s*<\s*\w+", regex::escape(param_name))` matches an
  unrelated substring: for a parameter named `n`, `n\s*<\s*\w+` matches
  inside `"gain < x"` or `"return < y"` — anywhere the letter `n` is
  immediately followed by `<`. Its `if\s*\([^)]*{}` pattern is broader
  still — it matches *any* `if (...)` whose condition contains the
  parameter name as a substring, unrelated to bounds. Short parameter
  names (`n`, `i`, `p`, `sz`) are common in C, so this will often report
  "bounds check found" when none exists, silently suppressing real
  ARR30-C violations. It also never runs `text_sans_comments_and_strings`,
  so a comment mentioning the pattern would fake a match too.
- **`has_lower_bound_check`** (5144-5163) — same shape, same missing-`\b`
  bug, feeding `check_return_pointer_arith_binary_expr`'s NULL/negative-
  offset check (3443).
- **`has_recursive_index_modification`'s regex family** (1640-1694, via
  `is_recursive_array_access`) — same missing-`\b` issue on the
  function-name/index-name substitution into `call_pattern`/
  `modification_pattern`, plus a second, independent bug:
  `depth_pattern = r"if\s*\(\s*\w+\s*>\s*(\d+)\s*\)"` matches the *first*
  `if (anything > N)` found anywhere in the function and assumes it's the
  recursion's depth guard, with no check that it actually relates to the
  recursion. A function with an unrelated early `if (retries > 3)` would
  have its actual (unguarded) recursive index growth misjudged as
  depth-limited.

This is a concrete, non-hypothetical false-negative class, and the
strongest candidate for what task 481's "hiding substantially more, not
clean" assessment was pointing at — not because the newer code is bad
(it's the opposite), but because this older layer still gates the same
violation paths and hasn't been brought up to the same rigor.

### 6.2 Intra-file duplication (same pattern task 497 found elsewhere in this file)

- **The "identifier-substring-contains-size/length/count" FN-risk
  heuristic appears twice**, verbatim in shape: `has_dynamic_bounds_check`
  (1764-1770, checks `size`/`length`/`count`) and
  `check_while_loop_pointer_increment`'s `has_bound_named_identifier`
  (3572-3580, adds `len`). Both treat *any* identifier merely containing
  one of those substrings (e.g. a variable named `green`, `calendar`,
  `silence`) as proof of a bounds check anywhere in the function/
  condition. Same class of false-negative risk as 6.1, but AST-scoped
  rather than raw-text, so narrower in practice.
- **`collect_param_decode_buffers`** (4027-4084) and
  **`const_char_ptr_params_without_length`** (4291-4333) implement
  near-identical parameter-scanning logic (is-pointer / is-const-char /
  is-int-scalar / "next param is length" convention) for two different
  call sites (`check_param_decode_overread` vs. the interprocedural
  helper-overread summary) — a clear candidate to factor into one shared
  helper, same shape as task 497's `find_identifier_in_declarator`
  finding.
- **`find_matching_param_declaration`** (3493-3517) uses raw
  `param_text.contains(offset)` to find which parameter a
  pointer-arithmetic offset name refers to — no word-boundary check, so a
  short offset name can match the wrong parameter in a multi-parameter
  function. This is in direct contrast to `is_function_parameter_any_return`
  (2442-2458), ~1000 lines earlier in the same file, which does this
  correctly via `.split(...).any(|w| w == var_name)` token matching. Same
  "one correct pattern already exists in-file, another function reinvents
  it wrong" pattern as task 497.

### 6.3 Not new / already resolved

`is_alloc_call` (4568) already calls `call_roles::is_allocator_call` —
task 498 landed and was validated (byte-identical Juliet/real-world) on
2026-08-22. Task 497's "already tracked, now unblocked" language for this
item is stale/confirmed-done, not a live gap.

---

## 7. ARR38-C per-library-function checking layer (task 512)

**Scope actually read:** `src/rules/cert_c/ARR/ARR38-C/arr38_c.rs` lines
86-2545 — the full `check()` entry point, all buffer/size/pointer-offset
collection helpers (`collect_buffer_info`, `extract_declaration_info`,
`extract_assignment_info`, `find_content_size_in_function`), and every
`check_*` dispatcher and leaf checker in the per-library-function family
(`check_node` -> `check_library_function_call` ->
`check_memory_function`/`check_string_function`/
`check_wide_memory_function`/`check_wide_string_function`/
`check_allocation_function`/`check_io_function`/`check_buffer_function`/
`check_array_function`, plus all their leaf helpers through
`is_short_string_source`). Somewhat larger than the original ~1500-line
estimate (closer to ~1900 lines) because the size/declaration-collection
helpers turned out to feed directly into this checking layer's
correctness and were read in full rather than sampled. Everything from
line 2546 (`find_array_size`) onward is the text-based size-parsing
family task 497 already scoped — not re-read here except to confirm the
boundary.

### 7.1 Latent risks/bugs, most significant first

1. **Unscoped whole-file text search in
   `is_unvalidated_function_parameter`/`has_size_validation`**
   (2424-2492, called from `is_potentially_user_controlled_in_source` ->
   `check_generic_size_heuristics`, which every `memcpy`/`memmove`/
   `memset`/`memcmp`/`memchr` call reaches). `is_unvalidated_function_parameter`
   does `source.find('{')` and slices `&source[..brace_pos]` to find "the
   function signature" — but `source` here is the **whole-file** source
   passed down from `check()`, not the containing function. `brace_pos`
   is the position of the *first* `{` in the entire file, so `header` is
   effectively "everything before the first function's opening brace"
   regardless of which function the call site is actually in.
   `has_size_validation` similarly does `source.contains(pattern)`
   against the whole file, so an `if (n > ...)` validation in *any*
   function suppresses the Heartbleed-pattern warning for `n` in *every*
   function. This is the exact "whole-file unscoped search" bug class
   task 496 already fixed for this same file's `find_array_size`/
   `find_string_literal_length` (section 2 above) — but these two
   functions were missed by that fix and still have it.
   `is_short_string_source`, defined a few dozen lines below at 2495,
   explicitly scopes to `find_containing_function` with a comment calling
   out precisely this cross-function contamination risk — the fix
   pattern already exists in the same file, just not applied here.
   Effect: false negatives (a real unvalidated user-controlled size in
   function B is suppressed because function A elsewhere validates a
   same-named variable) and occasional misattribution.
2. **Same unscoped-whole-file-search bug in `is_type_size_mismatch`**
   (2580-2615, used by `check_array_function`'s `qsort`
   element-size-mismatch check). `source.contains(pattern)` where
   `pattern` is a hardcoded declaration shape like `"int {array_name}["`
   searches the entire file, not the enclosing function — a same-named
   array declared with a different type in an unrelated function can
   trigger or suppress a mismatch verdict for the wrong function. Also
   independently brittle: only 8 hardcoded `type name[`/`type*name`
   spacing variants, misses typedefs, multi-declarator lines, and
   non-array-decl declarations of the same name.
3. **Dead code: `check_three_arg_size`** (1135-1162,
   `#[allow(dead_code)]`) — zero call sites anywhere in the file
   (grep-confirmed). Fully subsumed by `check_generic_size_heuristics`,
   which every live checker path already routes through.
4. **`check_io_function`'s struct-size heuristic looks like an
   undocumented Juliet-specific hack** (1406-1433): flags `fread`/
   `fwrite` when the size argument is a hardcoded number in `8..=64`
   divisible by 4 **and** (`buf_arg.contains("struct") ||
   source.contains("struct obj")`). The `source.contains("struct obj")`
   half is a literal, unscoped, whole-file substring search for one
   specific test-fixture identifier shape — same category already
   flagged for `sizeof_type`'s `"twoIntsStruct" => Some(8)` entry
   (section 2 above, flagged for removal at consolidation).
   Independently, the heuristic itself is generically weak and would
   false-positive on real-world code (e.g. `fread(buf, 16, 1, f)` where
   `buf_arg` merely contains the substring "struct").
5. **Coverage asymmetry between narrow (`char*`) and wide (`wchar_t*`)
   function families**: `memcpy`/`memmove`/`memset`/`memcmp` reach the
   full `check_buffer_size_mismatch` -> `check_generic_size_heuristics`
   pipeline (Heartbleed-style user-controlled-size check plus the
   general `is_dangerous_size_calculation` catch-all). `wmemcpy`/
   `wmemmove`/`wmemset` and `wcscpy`-family have their own separate,
   narrower ad hoc checks and never reach either generic heuristic — a
   plausible false-negative gap for wide-character variants of the same
   defect classes. Not confirmed against ground truth, just a structural
   asymmetry.
6. **`memcmp`/`memchr` get no pointer-offset checking**:
   `check_memory_function`'s dispatch gives `memcpy`/`memmove` both
   `check_pointer_offset_overflow` (dest) and `check_source_pointer_offset`
   (source), but `memcmp`/`memchr` go straight to
   `check_buffer_size_mismatch` with no pointer-offset check on either
   argument. A `memcmp(buf - 8, other, n)` underread would not be caught
   the way the equivalent `memcpy` call would be.
7. **`is_dangerous_size_calculation`'s heuristics are generically
   FP-prone** (1737-1799) — inherited risk this layer depends on heavily
   as the final catch-all in nearly every dispatch path: any size
   expression with a `+` that isn't `strlen`/`wcslen`-based and has zero
   `sizeof(...)` in it is unconditionally flagged as dangerous, which
   would flag a legitimately-validated `len + 1` just as readily as a
   real bug. Existing, shipped behavior — noted for future FP-reduction
   work, not a fresh bug.
8. **Declaration/assignment collection (`extract_declaration_info`/
   `extract_assignment_info`, 422-622) are text-substring-based, not
   AST-based**, unlike ARR30-C's equivalent (already AST-based per
   section 1). Scoped correctly per-node (not the unscoped whole-file
   problem above), but weaker than an AST walk — e.g. a declaration
   containing a comment mentioning `malloc(` would false-match. Not
   confirmed as an actual FP source in practice.

No new same-file self-duplication analogous to ARR30-C's
`find_identifier_in_declarator` (section 1) was found in this half — the
checking-layer dispatch structure is reasonably factored.

---

## 8. Task 512 follow-up tasks filed

Filed via `todo-sqlite-cli add ... --depends-on 512`:

- **ARR30-C**: word-boundary/sanitization fix for the three regex
  helpers (6.1); dedup of the size/length/count/len substring heuristic
  (6.2); dedup of `collect_param_decode_buffers`/
  `const_char_ptr_params_without_length` (6.2); token-boundary fix for
  `find_matching_param_declaration` (6.2).
- **ARR38-C**: scope `is_unvalidated_function_parameter`/
  `has_size_validation` to the containing function (7.1 #1); scope
  `is_type_size_mismatch` to the containing function (7.1 #2); delete
  dead `check_three_arg_size` (7.1 #3); remove/generalize the
  `"struct obj"` Juliet-specific hack in `check_io_function` (7.1 #4);
  investigate wide-character function heuristic-coverage parity (7.1 #5).

See each task's own details for exact acceptance bar and CLAUDE.md
delta-adjudication requirements where detection behavior changes.

### Status as of 2026-09-03

All nine are closed except 7.1 #5. Behavior-affecting items are marked; the
rest are refactors that left every verdict unchanged.

| Section | Task | Outcome |
|---|---|---|
| 6.1 | 678 | Closed. Word-boundary anchors + comment/string sanitization. **Changes detections.** |
| 6.2 | 679 | Closed. Both copies now call `subtree_has_bound_named_identifier`. Dedup only. |
| 6.2 | 680 | Closed. `const_char_ptr_params_without_length` is the single implementation. Dedup only. |
| 6.2 | 681 | Closed. Token-boundary match. Behavior-preserving except where it was misfiring. |
| 7.1 #1 | 682 | Closed. Scoped via `find_containing_function`. **Changes detections** (fixes a demonstrated FN). |
| 7.1 #2 | 683 | Closed. Scoped via `find_containing_function`. **Changes detections** (fixes a demonstrated FP). |
| 7.1 #3 | 684 | Closed. Dead code deleted. No behavior change. |
| 7.1 #4 | 685 | Closed by generalizing, not removing: `buffer_is_struct_typed` resolves the buffer's declared type instead of matching on its name or on a whole-file `"struct obj"` literal. **Changes detections** (fixes a demonstrated FP *and* FN). |
| 7.1 #5 | 686 | Still open. |

Two weaknesses noted while fixing the above are recorded but deliberately
NOT bundled, each being a behavior change wanting its own measurement:

- The substring-not-token match in `BOUND_NAME_SUBSTRINGS` (6.2) — a
  variable named `silence` or `discount` still reads as a bounds check.
  Documented at the constant.
- `is_type_size_mismatch`'s eight hardcoded declaration-shape patterns
  (7.1 #2) — typedef'd element types, multi-declarator lines and
  pointer-to-array declarations are all still missed. Documented on the
  function.

Items 7.1 #6 (no pointer-offset checking for `memcmp`/`memchr`), #7
(`is_dangerous_size_calculation`'s generic FP-proneness) and #8 (text-based
declaration collection) were never filed as tasks and remain open
observations.
