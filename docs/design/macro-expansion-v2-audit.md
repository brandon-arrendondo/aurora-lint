# Macro Expansion v2: Full Blast-Radius Audit & Design Recommendation

**Status:** Research complete (task 602, 2026-08-26). This is a **research
document only** — no rule/engine code was changed to produce it. It
supersedes/extends `docs/design/macro-expansion.md` (keep that file for
Phase 0-3 history); read this one for the current-state inventory and the
go-forward decision on tasks 199, 554, 573, 589.

**tl;dr recommendation:** do **not** build a general pre-expansion pass.
Extend `macro_expand.rs` with three narrow, targeted capabilities (one per
gated task). The consumer inventory below shows the blast radius of a real
expansion pass is large (15+ rules, several deliberately definition-side)
while the actual unmet need is three point capabilities, each cheap to add
to the existing per-rule-opt-in engine. See §3 for the full reasoning.

---

## 1. Full consumer inventory

### 1a. Shared engine (`src/analyze/macro_expand.rs`) — direct callers

| File | Function(s) called | Macro property relied on | Risk if replaced by real expansion |
|---|---|---|---|
| `src/rules/cert_c/MEM/MEM30-C/mem30_c.rs` | `macro_nulls_param_indices` | Structural: does the macro body free-then-null its param as a whole object? | Low — real expansion would just make the free+null visible in the CFG directly; the point function becomes redundant but behavior converges, not diverges. |
| `src/rules/cert_c/MEM/MEM31-C/mem31_c.rs` (via `function_summary.rs:1274`, `frees_param_fields`) | `macro_nulls_param_indices` | Same as above, applied to `FunctionSummary` computation instead of a rule directly | Low, same reasoning. |
| `src/rules/cert_c/MEM/MEM12-C/mem12_c.rs` | `collect_function_macros`, `macro_frees_param_indices` | Structural: does the macro release the param via `free`/`fclose`/`close`? | Low. |
| `src/rules/cert_c/EXP/EXP36-C/exp36_c.rs` | `collect_function_macros` | Opaque/value-only (inspects macro definitions, not dataflow effect) | Low. |
| `src/rules/cert_c/EXP/EXP33-C/exp33_c.rs` | `collect_function_macros`, `macro_output_param_indices` | Structural: does the macro assign a param as a whole object (`(param) = …`)? | **Medium** — real expansion would let the *general* init-state CFG walk see the assignment directly, which is strictly more precise (also catches conditional/partial writes the point-function's whole-object-only model misses). Task 589 needs this rule's model extended to *forwarding*-macros too (see §1c). |
| `src/rules/cert_c/EXP/EXP34-C/exp34_c.rs` | `macro_writes_param_indices` | Structural: writes through the pointer itself (`param->f=`, `param[i]=`, `*param=`), superset of output-param | Medium, same reasoning as EXP33. |
| `src/rules/cert_c/ARR/ARR30-C/arr30_c.rs` | `collect_function_macros` | Opaque/value-only, file-local (already migrated off its private duplicate per macro-expansion.md §10) | Low for this use; ARR30's *other* macro gap (task 554, allocation-size-expression) is a **separate, unaddressed property** — see §1c. |
| `src/analyze/prescan.rs` | `collect_function_macros` | Collection-only: builds the cross-file `ProjectContext::function_macros` table consumed by the callers above | N/A — infrastructure. |
| `src/analyze/function_summary.rs` | `macro_nulls_param_indices` | Structural, feeds `frees_param_fields` | Low. |

**Engine consumer count: 7 rules/utilities** (MEM30-C, MEM31-C, MEM12-C,
EXP36-C, EXP33-C, EXP34-C, ARR30-C) plus 2 infra call sites (prescan,
function_summary). This matches `docs/design/macro-expansion.md`'s
"Already on the engine" row (EXP33, EXP34, MEM30, DCL31, MEM31) **with one
drift**: DCL31-C does **not** actually call `macro_expand.rs` in current
source (no hit in the call-site grep) — the doc's row is stale on that
point (see §1d). MEM12-C is a real consumer not listed in that row at all
(it's newer than the doc's Phase-3 stock-take).

### 1b. `const_eval` idiom consumers (collect-per-file + merge-cross-file, task 199's target)

All of these call `src/analyze/const_eval.rs`'s `collect_macro_constants` /
`collect_macro_aliases` / `try_evaluate_*`, then merge with
`ProjectContext::macro_constants`/`macro_aliases` (per-file wins). This is
**value-only** macro handling — object-like `#define NAME value/expr`
constants and single-identifier aliases — categorically different from the
function-like-macro engine above.

| Rule | Macro property relied on | Risk if replaced by real expansion |
|---|---|---|
| INT30-C, INT32-C, INT33-C, INT34-C | Object-like constant value (used in overflow-guard/threshold detection) | Low — a real preprocessor would resolve the same values, typically more completely (recursive macro-of-macro, arithmetic on non-literal operands). Recall-neutral to positive. |
| FIO30-C | Object-like constant value | Low, same. |
| FLP03-C | Object-like constant (text-based, structurally incompatible per the capability catalog — flagged as its own migration, task 501, unrelated to this audit) | Low for value resolution; the FLP03-specific text-vs-AST mismatch is orthogonal to macro expansion and already tracked. |
| STR02-C | Object-like alias (`#define SYSTEM system`) | Low. |
| ERR33-C | Object-like constant | Low. |
| ENV03-C, ENV33-C | Object-like constant/alias, taint-relevant | Low. |
| DCL07-C | Object-like constant | Low. |
| ARR30-C | Object-like constant (loop-bound resolution, separate from its `macro_expand.rs` use above) | Low. |

**11 consumers**, matching the const_eval row in `macro-expansion.md` §10
exactly. Confirmed still accurate — no drift here. This category is
**not opaque-function-like-macro debt**; it is a pure DRY (task 199) that a
real expansion pass would not obviously improve, since these rules only
need scalar constant values, which `const_eval` already resolves
correctly for the common case. A real expansion pass **could** subsume
this (an expanded AST would just have the literal in place of the macro
token), but the win is marginal — `const_eval` already handles arithmetic,
`sizeof`, and standard limits.

### 1c. Ad-hoc heuristics found beyond the disposition table (drift + gaps)

A fresh broad grep for `"macro"` across all `src/rules/cert_c/**/*.rs`
(70 files matched, listed in the raw grep output) found several genuine
ad-hoc heuristics **not captured by either the engine or the const_eval
idiom, and not all listed in `macro-expansion.md`'s disposition table**:

| Rule | What it does | Macro property relied on | In disposition table? |
|---|---|---|---|
| MEM05-C | `is_likely_macro_constant`-style ALL_CAPS name guess | Naming heuristic, not value extraction | Yes ("keep", correctly) |
| ARR32-C | Same ALL_CAPS heuristic | Naming heuristic | Yes ("keep", correctly) |
| **MEM33-C** (`mem33_c.rs:2484`) | `// Strategy 3: Check for macro usage (must contain at least one uppercase letter…)` — same ALL_CAPS guess, independently reimplemented | Naming heuristic | **No — drift.** Should be added to the "Local `is_likely_macro_constant` name heuristic — KEEP" row alongside MEM05/ARR32. |
| **DCL03-C** (`dcl03_c.rs:186`) | `// Likely a macro constant` — same ALL_CAPS guess | Naming heuristic | **No — drift.** Same category. |
| **EXP08-C** (`exp08_c.rs:240`) | `// Don't flag macro constants (all caps)` | Naming heuristic | **No — drift.** Same category. |
| EXP44-C | `collect_generic_macros`: scans macro bodies for `_Generic` to avoid misclassifying macro-wrapped `_Generic` dispatch | Structural (definition-side, narrow, single-purpose) | Not applicable — this is a PRE/DCL-hygiene-adjacent definition-side check, correctly self-contained; no engine capability would help since it's about *whether a macro's body contains `_Generic`*, not about expanding it. |
| EXP47-C | Text-based fallback for `va_arg`-as-macro-call shapes | Structural, single-purpose | Not applicable — `va_arg` is a compiler builtin macro, not a project `#define`; out of scope for `macro_expand.rs`, which only collects `preproc_function_def`s. |
| MSC17-C | Detects `FALLTHROUGH()`-style marker macro calls (name/text match) for fallthrough-comment-or-macro equivalence | Naming/text heuristic, single-purpose, low risk | Not applicable — this is intentionally permissive (any spelling that looks like a fallthrough marker), not a dataflow property; real expansion doesn't apply (`FALLTHROUGH()` typically expands to nothing or an attribute). |
| POS35-C | Text search for `S_ISLNK(` usage | Naming/text heuristic | Not applicable — checking for *presence of a call*, not modeling an effect. |
| MEM03-C, MEM04-C | Comments only (macro-wrapped `free` call-site explosion noted; "could be a macro" fallback) — no distinct heuristic beyond generic name-based deallocator matching already covered elsewhere | N/A | N/A |
| FIO01-C, ERR06-C, CON09-C | Passing mention of macro-related CERT wiki wording or `assert()`/pthread naming; no rule-specific macro logic found | N/A | N/A |
| PRE00-13, PRE30-32, MSC38, MSC41, API10, API03, DCL37, EXP44 (dup), DCL19, DCL15 | Definition-side hygiene / naming / declaration rules | Deliberately raw-source view (macro hygiene rules must see `#define` as written) | Yes ("keep") — spot-checked, still accurate. |
| MSC13, MSC37, MSC07, DCL40, DCL30, SIG31, ARR01, ARR36, API00 | Incidental `preproc_*` AST-kind skip/recurse during normal traversal, no macro semantics | N/A | Yes ("keep") — spot-checked, still accurate. |

**Drift summary:** the disposition table's "Local `is_likely_macro_constant`
name heuristic — KEEP" row undercounts by at least 3 (MEM33-C, DCL03-C,
EXP08-C also do this, independently reimplemented rather than sharing a
helper). This is real duplication — a candidate for a **small, separate**
DRY task (extracting a shared `looks_like_macro_constant_name(&str) -> bool`
into `src/utility/cert_c/`), but it is a naming heuristic, not a macro-
expansion-engine gap, and is out of scope for the engine-vs-pass decision
this task is gating. Recommend filing it as its own low-priority tech-debt
ticket, not folding it into 199/554/573/589.

**RESOLVED (task 603, v0.4.288):** filed and done as its own tech-debt
ticket. The shared helper landed as
`utility::cert_c::ast_utils::is_likely_macro_constant` (named for the
existing per-rule spelling, not the `looks_like_macro_constant_name`
proposed above), and MEM05-C, ARR32-C, MEM33-C and DCL03-C now call it.
EXP08-C's copy turned out to be **unreachable dead code** — the preceding
`if node.kind() == "identifier"` branch returns unconditionally, and `text`
is lowercased before the check, so `is_uppercase()` could never hold — and
was deleted rather than wired to the shared helper; whether that exclusion
should be made live is a behavior question, tracked as task 618. Gated
byte-identical over the full Juliet suite (58,784 files, 4,457 findings) and
**all 9 real-world projects at their pinned commits** (1,345 findings: curl
100, hostap 447, libcrc 0, lua 16, mosquitto 27, sqlite 506, pureftpd 29,
raylib 80, seL4 140). The only divergence the consolidation introduces is
that DCL03-C's identifier check is now ASCII-only rather than Unicode
`is_uppercase()`, which no corpus file exercises.

### 1d. The three gated capability gaps (tasks 573, 589, 554)

| Task | Rule | Macro property needed | Currently modeled by |
|---|---|---|---|
| 573 | DCL41-C | **Structural/control-flow**: `CASE(n, "…")` expands to `case n: …;` — a case *label*, invisible to a rule that pattern-matches `case_statement`/`default` node kinds directly against the raw parse. Confirmed by reading `dcl41_c.rs`: it has **zero** macro awareness of any kind (no `macro`, no `preproc` handling beyond the generic node-kind list) — the macro invocation parses as a plain `expression_statement`, which the rule's `is_statement_or_declaration` correctly (but wrongly, for this case) classifies as "code before the first case label." | Nothing today. Neither the engine nor const_eval nor any ad-hoc heuristic touches DCL41-C. |
| 589 | EXP33-C | **Forwarding-call**: `Curl_rand(a,b,c)` macro's body is *itself* just a call to `Curl_rand_bytes(a,b,c)`, a real analyzable function whose `FunctionSummary.modifies_params` already knows it writes through its buffer arg. `macro_output_param_indices` only inspects the macro's own body *text* for a `(param) = …` assignment shape — a body that is nothing but a forwarded call has no such assignment, so it returns empty. | `macro_expand.rs`'s existing output/write functions (miss this case by design — they model direct writes, not indirection through another function). `function_summary.rs::modifies_params` already has the answer for the *forwarded* function, but nothing connects a macro invocation to it. |
| 554 | ARR30-C | **Allocation-size-expression**: `SZ(n)` macro (e.g. curl/sqlite-style `sizeof(struct X) + (n)*sizeof(T)`) is the argument to `malloc`/`sqlite3_malloc`. `buffer_size.rs::calculate_malloc_size`/`calculate_alloc_bytes` do **regex/text parsing directly on the call's argument text** (`N * sizeof(TYPE)` patterns) — when the argument is `SZ(n)` (a macro call, not a literal arithmetic expression), the text parser has nothing to match; ARR30-C falls back to the flexible-array member's *declared* size (`T a[1]`) instead of the *malloc'd* real count. | `buffer_size.rs` (text-based, macro-blind); ARR30-C's own `find_flexible_array_structs`/`check_flexible_array_malloc` (structural, but only for the literal-arithmetic case, not a macro-wrapped size expression). Neither `macro_expand.rs` nor `const_eval.rs` currently resolves a macro to a *size expression* rather than a scalar constant or a param-write index. |

None of these three needs is met by any *existing* capability in
`macro_expand.rs`, `macro_semantics.rs`, or `const_eval.rs`. Each is a
genuinely new macro *property* the engine doesn't yet model:
structural-expansion-of-invocation, call-forwarding-resolution, and
size-expression-substitution, respectively — confirming the task
descriptions' own framing.

---

## 2. Cross-check against `docs/design/macro-expansion.md`'s disposition table

Re-verified every row in §10's table against current source:

- **"Already on the engine" (EXP33, EXP34, MEM30, DCL31, MEM31):** DCL31-C
  does not currently call any `macro_expand.rs` function (no hit in the
  exhaustive `collect_function_macros`/`macro_*_param_indices` grep across
  `src/`). This is drift — either DCL31-C's engine wiring was reverted at
  some point, or the doc was inaccurate when written. Given this audit's
  scope is macro-expansion design (not fixing DCL31-C), flag it as a
  follow-up spot-check, not something to fix here.
- **"Engine duplicate — MIGRATE" (ARR30):** confirmed done — ARR30-C now
  calls the shared `collect_function_macros` (verified at
  `arr30_c.rs:226`, with an explicit comment noting the migration from its
  former private extractor). No longer duplicated for *this* property.
  ARR30-C's task-554 gap is a **different, new** property (size-expression),
  not a regression of the migrated one.
- **"const_eval consumers — DRY candidate":** confirmed accurate, 11/11
  match (§1b above).
- **"Definition-side hygiene… — KEEP" and "Incidental preproc traversal —
  KEEP":** spot-checked several from each list; still accurate.
- **"Local is_likely_macro_constant name heuristic — KEEP" (MEM05, ARR32):**
  undercounted — see §1c drift note (MEM33-C, DCL03-C, EXP08-C also do
  this). *Fixed in task 603: row now reads MEM05, ARR32, MEM33, DCL03 and
  all four share one helper; EXP08-C's copy was dead code, deleted.*

---

## 3. Design evaluation: real expansion pass vs. targeted extensions

### 3a. Would a real pre-expansion pass subsume all three gaps + the ad-hoc consumers?

**In principle, yes** — a real preprocessor-equivalent stage (Approach C in
`macro-expansion.md`, or a more ambitious version of Approach B extended to
splice expanded text into the parsed tree before *all* rules run, not just
opt-in per-rule lookups) would make `CASE(n,"…")` literally become `case n:
…;` in the tree DCL41-C walks, make `Curl_rand(a,b,c)` literally become
`Curl_rand_bytes(a,b,c)` so ordinary call-based `FunctionSummary` lookup
"just works," and make `SZ(n)` literally become `sizeof(struct X)+(n)*
sizeof(T)` so `buffer_size.rs`'s existing text parser would already handle
it, no new code needed. In that sense a real pass is strictly more general
than three point-fixes — this was already `macro-expansion.md`'s own
conclusion for Approach B/C, and remains true.

**But this audit's inventory changes the cost side of that trade, not the
benefit side, and the cost side is what matters here:**

1. **The blast radius is large and heterogeneous.** §1 found ~15 rules
   actively depending on macro *opacity* being preserved or on the
   *current* narrow semantics, not just rules that would benefit from
   expansion:
   - The entire PRE0x/PRE1x/PRE3x/MSC38/MSC41/API10/API03/DCL37/DCL19/DCL15
     "definition-side hygiene" set (§1c, "keep" rows) **must see the macro
     as written** — a destructive or even parallel-view expansion pass
     that isn't perfectly scoped risks these rules silently losing their
     signal (e.g. a reserved-identifier `#define` check operating on
     already-expanded text would have nothing to check).
   - The engine consumers (§1a) already get a **correct, narrow, false-
     positive-safe answer** for their specific property (output-param,
     null-param, frees-param). Re-deriving the same answer from a general
     expansion would be strictly more work for no behavior change in the
     common case (per-consumer "risk if replaced" column is Low for most).
   - The naming-heuristic rules (MEM05, ARR32, MEM33, DCL03, EXP08) don't
     need expansion at all — they're guessing about *undefined* macros
     (the constant isn't collectible, that's the whole reason for the
     guess); an expansion pass can't help a macro whose definition isn't
     in scanned files any more than `const_eval` can.
2. **A real pass reintroduces exactly the risks `macro-expansion.md`
   already rejected Approach C for** (§4/§5 of that doc): source-location
   fidelity for findings, a second raw-parse requirement to keep PRE-rules
   working, and — new since that doc was written — now a demonstrably
   *larger* migration surface than the "~51 files" estimate that doc's own
   Phase-3 stock-take (§10) already corrected down to "ARR30 + optional
   DRY." Reopening the full-pass question would be re-litigating a
   decision the codebase has already made progress walking back from.
3. **The three actual gaps are narrow and independent of each other.**
   Structural case-label exposure (573), forwarding-call resolution (589),
   and size-expression substitution (554) do not share an implementation —
   each is a different function alongside the existing four in
   `macro_expand.rs`, consumed by exactly one rule. There is no shared
   plumbing gap forcing a bigger architecture; the engine's existing
   "collect once, query per-property" shape already accommodates adding a
   fifth, sixth, seventh query function.

### 3b. Cost/complexity/regression-risk comparison

| | Targeted extensions (recommended) | Real expansion pass |
|---|---|---|
| New code surface | 3 new functions in `macro_expand.rs`, each consumed by exactly 1 rule | A new pre-parse or parallel-AST-rewrite stage touching every rule's input |
| Consumers requiring rework | 0 existing consumers change (additive) | Up to ~15 rules need audit/rework to confirm they still see what they need (PRE/definition-side set especially) |
| Regression surface (Juliet) | Isolated to DCL41-C/EXP33-C/ARR30-C's own test suites | Every rule that touches a `preproc_function_def` or macro invocation, i.e. potentially the whole suite |
| Regression surface (real-world) | 3 targeted FP-driver fixes, each independently gateable per CLAUDE.md's delta-adjudication protocol | Single large gate covering all consumers at once — harder to isolate a regression to its cause |
| Effort (rough) | Days each, ~1-2 weeks total for all 3 | Weeks, per `macro-expansion.md`'s own §7 estimate for Phase 2 (1-2 weeks) *before* accounting for the now-larger migration list in §1 |
| Precedent | Matches the existing `macro_expand.rs` design (opt-in per-rule query functions) | Would be a second architecture living alongside the first, since PRE-rules still need the current raw-parse mechanism regardless |

The targeted-extension path wins clearly: lower cost, isolated regression
surface, no rework of rules that are working correctly today, and no
re-opening of an architectural debate the project already resolved (favor
Approach B/D, reject C).

### 3c. Per-rule migration/rework list — **not applicable**

Because the recommendation is targeted extensions rather than a real
expansion pass, there is no migration list to scope. If a future volume of
gaps changes this calculus (see §4 trigger condition), the migration list
would need to itemize, for every row in §1a/§1b/§1c: whether the rule's
current lookup-function call is replaced by direct AST inspection of
expanded text (§1a rows — all "would converge", low risk), whether the
rule needs to keep its *own* raw view alongside the expanded one (all §1c
"keep" rows — mandatory dual-view, non-trivial), and whether const_eval's
scalar resolution becomes redundant (§1b rows — likely yes, but marginal
benefit as noted).

### 3d. Disposition for tasks 573, 589, 554

All three: **fix now as targeted extensions to `macro_expand.rs`.** None
should wait for a unifying pass, because no unifying pass is recommended.

- **Task 573 (DCL41-C structural expansion):** Add a narrow, DCL41-C-
  specific helper — e.g. `macro_case_label_indices(table, name) ->
  Vec<i64>` or a `is_structural_case_macro` predicate — that inspects a
  macro's body for a `case N:`/`default:` label shape (paralleling how
  `macro_output_param_indices` inspects for an assignment shape) and, in
  `dcl41_c.rs`, treat a call to such a macro the same as an actual
  `case_statement` when scanning for the first label. Scope narrowly to
  the label-detection question only — do not build a general "expand
  control-flow macros into the CFG" mechanism; DCL41-C's structural check
  doesn't need dataflow, just "is this position a case label."
- **Task 589 (EXP33-C forwarding-macro):** Add a
  `macro_forwarded_call_name(table, name) -> Option<(String, Vec<usize>)>`-
  style helper: recognize a macro whose entire body is a single
  `call_expression` whose arguments are the macro's own parameters (in
  order, or via an explicit positional mapping), returning the forwarded
  function's name and the parameter-index mapping. In `exp33_c.rs`, when
  a macro invocation resolves this way, look up the forwarded function's
  `FunctionSummary.modifies_params` (already available via
  `ProjectContext::function_summaries`) instead of (or in addition to)
  `macro_output_param_indices`. Per the task's own precision-risk note,
  gate strictly on *positional identity* (reject reordered/dropped-arg
  forwarding) to avoid introducing false negatives.
- **Task 554 (ARR30-C allocation-size-expression):** Add a
  `macro_expand_size_expression(table, name, args) -> Option<String>` (or
  reuse `expand_invocation`, which the engine already has, then feed the
  *expanded text* into `buffer_size.rs`'s existing
  `calculate_malloc_size`/`calculate_alloc_bytes` regex parsers instead of
  the raw macro-call text). This is the cheapest of the three: the size-
  expression parser already exists and already handles `sizeof(struct)+n*
  sizeof(T)` shapes — the only gap is that ARR30-C hands it a macro-call
  string today. Wiring `expand_invocation`'s output into that existing
  parser (rather than inventing new size-expression parsing) is a small,
  low-risk change confined to ARR30-C's malloc-argument-text extraction
  step.

Each should still go through Juliet + real-world delta-adjudication gating
per CLAUDE.md's protocol before being called "fixed," same as any other
rule-logic change — this document only clears the *design* gate (602), not
the *implementation* gate.

---

## 4. When to revisit the "no general pass" call

Re-open this decision only if a **fourth or fifth** distinct macro-property
gap surfaces that (a) is not a property `macro_expand.rs` can absorb as a
single new query function, and (b) recurs across multiple rules rather than
being specific to one. Nothing found in this audit meets that bar today —
573/589/554 are three independent single-rule gaps, and the const_eval/
naming-heuristic consumers found in §1b/§1c don't need expansion at all.
Task 199 (const_eval DRY) remains a separate, low-priority mechanical
refactor, unaffected by this recommendation — it can proceed independently
once un-gated.
