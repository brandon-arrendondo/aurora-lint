# Scoping: Macro Expansion in sqc

**Status:** IMPLEMENTED (as of 2026-07-22; originally scoped 2026-06-16).
The engine described here (`src/analyze/macro_expand.rs`,
`FunctionMacro`/`collect_function_macros`/`macro_nulls_param_indices`/
`macro_output_param_indices`) is live and wired into MEM30-C, MEM31-C,
EXP33-C, and DCL31-C. **The line above is the one fact to check before
assuming this is unimplemented** — Phases 0-3 below are historical
narrative from when it was being built; see §10 and the "Already on the
engine" row of the disposition table for current status. Do not
reimplement macro-invocation detection with a name heuristic (e.g.
matching `*_free`/`*_FREE` by string) without first checking whether
`context.function_macros` + the helpers above already solve it
name-independently — this has been done by mistake at least once (task 2,
MEM31-C, v0.4.117-119, before the engine was wired in at v0.4.120).
**Driver:** Recurring, codebase-independent false positives rooted in sqc's
inability to see through C macros. Tracked from task 180 (EXP33/EXP34 macro
opacity), but the problem is broader than two rules.

---

## 1. Problem statement & evidence

sqc analyzes **raw, un-preprocessed C source**: each file is read with
`fs::read_to_string` (`src/analyze/mod.rs:428`) and parsed by tree-sitter-c
(`CParser` / `tree_sitter::Parser`, `src/analyze/mod.rs:204,301`). **There is no
C preprocessor pass.** Consequently:

- Function-like macro **invocations** are never expanded. The dataflow analyses
  (init-state, null-state, VRA, CFG) cannot see the code the macro generates.
- Macro **definitions** are visible in the tree (tree-sitter exposes
  `preproc_def`, `preproc_function_def`, `preproc_arg`, the `preproc_if*`
  family), but nothing consumes a function-like macro's *body* to model its
  effect — the 23 `preproc_function_def` references in the codebase all
  inspect the definition (for PRE-rules / declaration rules), none expand it.

### Measured impact (mosquitto oracle, exhaustive per-finding)

| Rule  | Findings | TP | FP  | Macro-attributed FP |
|-------|---------:|---:|----:|---------------------|
| EXP33 | 266      | 0  | 266 | ~190 (DL_/LL_ FOREACH ~123, HASH_* ~81) |
| EXP34 | 149      | 7  | 141 | ~75 (DL_FOREACH loop-guard ~54, HASH_* ~18) |

These are utlist (`DL_FOREACH_SAFE`, `LL_FOREACH`) and uthash (`HASH_FIND`,
`HASH_ITER`) — ubiquitous single-header C libraries. The same patterns recur on
sqlite and will recur on **any** C project using these libraries, which is why
the cross-validation flagged it as a shared root cause (see
`data/precision_audit/mosquitto/adversarial_verification.md`,
memory `mosquitto-cross-validation`).

### Breadth (tech-debt surface)

**51 of 290 rule files (~18%)** already carry bespoke macro logic
(`FOR_EACH_MACROS`, `match_initializing_function`, `macro_constants`,
`macro_aliases`, per-rule `preproc_*` handling). Each rule reinvents a partial,
inconsistent model of what macros do. This scoping exists to decide whether to
keep paying that per-rule tax or build the capability once.

---

## 2. Current macro handling (what exists today)

All macro awareness is **definition-side and narrow**, collected in prescan
(`src/analyze/prescan.rs`) via `const_eval`:

- `macro_constants: HashMap<String,i64>` — object-like `#define N 42` → integer
  value only. No string/expression/typed constants beyond i64.
- `macro_aliases: HashMap<String,String>` — `#define ALIAS identifier`
  (e.g. `SYSTEM`→`system`) so rules can resolve calls through one level of
  indirection.
- `string_literal_macros` — object-like macros whose body is a string literal.

**This collection happens in a cross-file caching pre-pass**, which is the key
lever for macro expansion. `prescan_directories` walks **every file including
headers** and builds a `ProjectContext` (`src/analyze/context.rs:12`) that is
`bincode`-serialized to `data/prescan_cache/<project>.cache`
(`ProjectContext::save_to_file`/`load_from_file`, `context.rs:94-103`) and reused
across runs. It already carries cross-TU data: `function_summaries`, `call_graph`,
`macro_constants`, `macro_aliases`, `struct_field_types`, `global_*`. Because the
pre-pass crosses file boundaries, **a function-like macro defined in a vendored
header (e.g. `mosquitto/deps/utlist.h`) is collectible at pre-pass time even when
analyzing a `.c` that merely includes it** — and cached, so analysis-time
expansion never re-walks headers. This is where the macro-definition database
belongs.

Invocation-side modeling is per-rule and hand-maintained, e.g.:
- `init_state.rs:308` `FOR_EACH_MACROS` — a hardcoded list of BSD `<sys/queue.h>`
  iterator macros; marks **only the first identifier arg** initialized
  (`init_state.rs:1051`). This is *wrong* for utlist/uthash, where the head is
  the input (arg 0) and the iterator/temp/out vars are later args.
- `init_state.rs:186` `match_initializing_function` / `get_output_arg_indices` —
  output-arg tables for known initializing functions.

Tree-sitter also produces `ERROR` nodes around some macro constructs, already
worked around in places (`init_state.rs:946`). Parse robustness is therefore a
standing concern any expansion design must handle.

---

## 3. Taxonomy of macro-induced failures

A solution must be evaluated against the *whole* taxonomy, not just FOREACH:

1. **Control-flow macros** — `DL_FOREACH_SAFE`, `HASH_ITER`, `TAILQ_FOREACH`,
   project `LIST_FOR_EACH`. Expand to `for`/`while` with init + guard + step.
   Break init-state, null-state, and loop modeling. *(highest volume today)*
2. **Output/init macros** — `HASH_FIND(...,out)` sets `out`; `va_start`-style.
   Break init-state and null-state (var looks never-assigned).
3. **Guard / assert macros** — `BUG_ON(x)`, `assert_like(p)`, `likely(p)`.
   Hide null/range guards → downstream null-deref / overflow FPs.
4. **Object-like constants beyond i64** — `#define MAX (a+b)`, sizeof exprs,
   enum-like. Partially handled (i64 only); breaks VRA/bounds rules.
5. **Function-wrapper macros** — `#define foo(x) real_foo((x),__FILE__)` —
   call-graph indirection; partly handled by `macro_aliases` (one level).
6. **Token-paste / stringize** (`##`, `#`) — name synthesis; rarely dataflow-
   relevant but blocks naive expansion.
7. **Conditional compilation** (`#if/#ifdef`) — branch selection changes which
   code exists. Orthogonal but interacts (which macro def is live).
8. **Macros that should stay UNEXPANDED** — the PRE ruleset (PRE10, PRE11,
   PRE12, PRE02, PRE09…) audits macro *hygiene* and must see source as written.
   Any expansion must be a *parallel view*, not a destructive rewrite.

---

## 4. Constraints & design principles

- **Preserve the no-build-system model.** sqc runs per-file / per-directory with
  sibling-header prescan; there is no `compile_commands.json`, include-path, or
  toolchain integration anywhere in `src/`. This is a deliberate usability
  property (point sqc at any tree, get results). A solution that *requires* full
  build config is a different product.
- **Recall safety is non-negotiable.** Expansion must never *hide* a genuine
  uninitialized read, null deref, or overflow. Validate Juliet recall stays flat.
- **PRE-rules need the raw view.** Expansion is additive context for dataflow
  consumers, not a replacement of the parsed tree.
- **Source-location fidelity.** Findings must map to the original file:line the
  user can see, not to expanded/synthetic text.
- **Performance.** Prescan already walks every file; expansion must be lazy /
  cached (prescan cache exists in `data/`).

---

## 5. Approaches

### A. Per-macro semantic allowlist (status quo, extended)
Hardcode each external macro's dataflow effect (what task 180 was about to do:
add utlist/uthash to `FOR_EACH_MACROS` + mark the right arg indices).

- **Pros:** trivial, surgical, no architecture change, immediate FP win on the
  dominant libraries.
- **Cons:** does not generalize (every new project's macros reappear as FPs);
  unbounded maintenance; already 51 rule files of this debt; cannot model
  control flow, only point effects ("arg N is initialized").
- **Verdict:** acceptable **stopgap** for the top-2 libraries; not the answer.

### B. In-tree selective function-like macro expansion
Build a mini-expander over macro **definitions sqc already parses**
(`preproc_function_def` in the file + prescanned sibling/included headers). When
a dataflow analysis encounters a function-like macro invocation, substitute the
body (argument substitution, `#`/`##`, nested rescan), parse the expanded
snippet, and splice the resulting nodes into the CFG/dataflow for that site.

- **Pros:** generalizes to *any* macro whose definition is in scanned files
  (project macros + vendored single-header libs like utlist/uthash, which ARE
  in-tree); keeps raw-source model; additive (PRE-rules unaffected); correct for
  the common case.
- **Cons:** real work — a substitution engine with the awkward bits (`#`/`##`,
  variadic `__VA_ARGS__`, recursive/self-referential macro rescanning rules,
  argument pre-expansion). Must handle tree-sitter ERROR nodes around
  `MACRO(args){block}`. Cannot expand macros from **unscanned system headers**
  (e.g. glibc, `<sys/queue.h>`) — those have no definition in the tree.
- **Verdict:** the right general mechanism; bounded by "definition must be
  visible."

### C. Full external preprocessor (`cpp`/`clang -E`)
Shell out to a real preprocessor, parse the fully-expanded translation unit, map
locations back via `#line`.

- **Pros:** 100% correct expansion incl. system headers; reuses a battle-tested
  preprocessor.
- **Cons:** requires include paths / `compile_commands.json` → **breaks the
  no-build-system model** (§4); system-header expansion explodes TU size (10–100×)
  and slows analysis; `#line` back-mapping is fiddly and error-prone; destroys
  the as-written view PRE-rules need (would need a *second* raw parse anyway);
  introduces a toolchain dependency. A big ecosystem change for correctness on a
  minority of cases.
- **Verdict:** rejected as the default path; possibly an *opt-in* mode later for
  users who already have `compile_commands.json`.

### D. Hybrid — B + curated external-library macro-semantics registry  *(recommended)*
Combine in-tree expansion (B) with a small, declarative **registry of dataflow
semantics for ubiquitous external macros whose definitions are NOT in the tree**
(BSD `<sys/queue.h>`, and any system-header macro that matters). The registry
describes effects, not bodies: "iterator macro; arg i = iterator (init +
non-null inside body); arg j = temp (init); arg k = out (init, may-be-null)".
This subsumes and replaces the scattered `FOR_EACH_MACROS` / `get_output_arg_indices`
tables with one shared model consumed by init-state, null-state, and VRA.

- **Pros:** generality of B where definitions exist; a *single*, auditable
  semantic model for the handful of definition-less system macros that matter,
  instead of 51 files of ad-hoc lists; recall-safe (effects are conservative and
  reviewed).
- **Cons:** registry is still hand-curated (but small and centralized, not
  per-rule); two code paths (expand vs. model) to keep coherent.
- **Verdict:** best balance. B handles the long tail (project + vendored
  single-header libs); the registry handles the short list of system macros.

---

## 6. Recommendation & phasing

Adopt **D**, delivered in phases so each lands a measurable FP win and is
recall-gated independently:

- **Phase 0 — Spike & feasibility (small).** Confirm exactly how tree-sitter
  parses `MACRO(args){block}` (call_expression + sibling compound vs. ERROR),
  and how reliably `preproc_function_def` bodies + args are recoverable for
  utlist/uthash as vendored in real projects. Decide the splice representation
  (re-parsed sub-tree vs. synthetic dataflow events). Output: a go/no-go note
  appended here.
- **Phase 1 — Shared macro-semantics registry (replaces task 180 hack).**
  One module modeling iterator/find/output macros (utlist + uthash + BSD queue)
  as dataflow effects; consumed by init-state (EXP33) and null-state (EXP34).
  Retire `FOR_EACH_MACROS`'s first-arg-only logic. *This alone is projected to
  remove ~190 EXP33 + ~75 EXP34 FP on mosquitto with zero recall change* (the
  effects are init/guard, never suppression of a real defect).
- **Phase 2 — In-tree function-like expansion engine.** The general substitution
  engine for definitions present in scanned files; feeds the CFG/dataflow.
  Generalizes beyond the registry to project-local macros. **Source the
  definitions from the prescan caching pre-pass (§2):** add a
  `function_macros: HashMap<String, MacroDef>` field to `ProjectContext`
  (name → params + `preproc_arg` body text + source loc), populated during
  `prescan_directories` and carried in the bincode cache. Because the pre-pass
  already crosses headers, this captures vendored single-header libs
  (utlist/uthash) and project macros once, cached — analysis-time expansion is a
  lookup, not a re-walk. NB: adding a `ProjectContext` field changes the bincode
  layout of sqc's `--save-prescan`/`--load-prescan` cache format (see
  `src/analyze/context.rs`); bump a cache-format version if that CLI-level cache
  is ever used. The benchmark runners do not use it (task 209: measured ~10%
  wall-time savings on sqlite, not worth the staleness risk — every benchmark
  run is a fresh in-memory prescan). The registry (Phase 1) remains the
  fallback for macros with **no** collected definition (system headers like
  `<sys/queue.h>`).
- **Phase 3 — Migrate existing rules onto the shared model.** Replace the ~51
  files of ad-hoc macro logic with the Phase-1/2 infrastructure; delete dead
  tables. Pay down the debt.
- **Phase 4 (optional, opt-in) — `compile_commands.json` preprocessed mode**
  for users who want full system-header correctness, behind a flag, never the
  default.

Phases 1→3 each ship behind a Juliet-recall gate and a real-world FP-delta check
(sqlite + mosquitto). Phase 1 unblocks GATE task 171 on the macro-opacity front.

---

## 7. Effort / risk (rough)

| Phase | Effort | Risk | Payoff |
|------:|--------|------|--------|
| 0 | ~0.5 day | low | de-risks 1–2 |
| 1 | ~2–3 days | low (additive, recall-gated) | ~265 mosquitto FP; recurs on every utlist/uthash project |
| 2 | ~1–2 weeks | medium (substitution correctness, ERROR-node robustness, perf) | general project-macro coverage |
| 3 | ~1 week | medium (regression surface across 51 files) | debt paydown, consistency |
| 4 | ~1 week | high (build-config integration, perf) | system-header correctness, opt-in only |

---

## 8. Validation plan (every phase)

1. Juliet full suite — recall must not drop (esp. CWE-457/EXP33, CWE-476/EXP34,
   CWE-190/INT3x). Compare via `compare_runs`.
2. Real-world sqlite + mosquitto — measured precision via the ground_truth
   oracle (`python3 -m bench realworld-score`); expect FP down, TP flat.
3. Per-phase: targeted `.c` regression cases under each affected rule's
   `tests/pass` (must-not-flag) and `tests/fail` (must-still-flag).

---

## 8a. Phase 0 spike results (2026-06-16, task 184) — GO

Verified against sqc's **exact grammar** (tree-sitter-c 0.21) via
`examples/dump_ast.rs` (a kept dev tool: `echo CODE | cargo run --example dump_ast`).

**Parse shapes (authoritative):**
- **Block-bearing macros** (`DL_FOREACH_SAFE(head,el,tmp){…}`, `HASH_ITER(…){…}`):
  parse as `expression_statement → call_expression(function=<MACRO>,
  argument_list=[head,el,tmp])`, followed by a **`MISSING ";"`**, then a
  **detached sibling `compound_statement`** (the body) at the same level.
  `has_error = true`, but the structure is fully navigable by AST position:
  macro name + positional identifier args are clean, and the body is the
  immediately-following sibling block.
- **Non-block output macros** (`HASH_FIND_INT(users,&id,out); if(out){…}`):
  parse **cleanly** (`has_error = false`); `out` is a positional arg identifier
  and the `if(out)` guard is a normal `if_statement`.
- **Definitions** (`#define M(a,b,c) …`): `preproc_function_def` → `identifier`
  name + `preproc_params` + body as a single `preproc_arg` **text blob** —
  name/params/body all recoverable (Phase 2 substitutes into this text).

**Premise reproduced** on current sqc for the FOREACH snippet:
`EXP33 'el'/'tmp' used uninitialized` (at the arg positions) + `EXP34 'el'
potential null deref` (inside the body) — i.e. exactly the oracle FPs. The
detached body **is** visited by the CFG (the EXP34 hit lands inside it), so
state set at the call statement propagates into the body. Fixture saved at the
snippet in this section; promote to `tests/pass` in Phase 1.

**Vendoring (answers §9):** mosquitto vendors `deps/utlist.h` + `deps/uthash.h`
in-tree, so Phase 2 expansion can reach those definitions *if* prescan scans
`deps/`. But `<sys/queue.h>` is a system header (not in-tree) — confirming the
hybrid (§5 D): registry for definition-less system macros, expansion for the
in-tree long tail.

**Splice decision for Phase 2:** prefer modeling block-macros as a *synthetic
loop* (treat the following sibling `compound_statement` as the body, the
positional args per the registry) rather than literal text re-expansion — the
detached-block + MISSING-";" shape makes positional AST modeling simpler and
more robust than re-lexing `preproc_arg` and re-parsing. Reserve full text
expansion for non-control-flow function-like macros.

**Verdict: GO.** Phase 1 (task 180) is unblocked; the registry is positional
(per-macro arg roles: iterator / temp / out / head-input) consumed by init-state
(mark outputs Initialized) and null-state (mark iterator/out NotNull within the
following block).

## 8b. Phase 1 results (2026-06-16, task 180) — DONE

Shipped `src/analyze/macro_semantics.rs`: a positional registry (iterator table:
utlist/uthash `*_FOREACH[_SAFE]`, `HASH_ITER`, BSD `<sys/queue.h>`) plus a
prefix-matched `HASH_FIND*`/`HASH_REPLACE*` family (output = last arg, so new
variants are covered without enumeration). Consumed by init-state (EXP33: mark
iterator/temp/out args initialized), the EXP33 read-check (skip output-arg
positions), and EXP34 (`is_unsafe_at`: iterator var is non-null inside the body
block). Released as 0.4.34 → 0.4.35 (family fix). Replaced the old first-arg-only
`FOR_EACH_MACROS`.

**Same-version A/B (mosquitto, pinned commit `d3ee5c5c`, identical harness command,
0.4.33 baseline vs 0.4.35):**

| | 0.4.33 | 0.4.35 | Δ |
|---|---:|---:|---:|
| Total findings | 12,534 | 12,105 | **−429** |
| EXP33-C | 488 | 176 | **−312** |
| EXP34-C | 503 | 386 | **−117** |
| **Net-new findings** | — | — | **0** |

**Recall gate (Juliet fast, 0.4.33 vs 0.4.34):** CWE-457/EXP33 TP 506 / FP 31 and
CWE-476/EXP34 TP 370 / FP 175 — *identical*. The change is additive suppression
on macros absent from Juliet, so recall is provably unchanged. sqlite real-world
was essentially unchanged (it does not vendor utlist/uthash) — confirming this
was a mosquitto-class problem, and (per the project principle) sqlite's own
macro FPs would be addressed by hardening, not by disabling.

**Method note:** the A/B was the gold standard precisely because comparing to the
0.4.30 audit numbers is contaminated by 4 versions of intervening change + scope
differences. The A/B also *caught a completeness gap* (HASH_FIND_BYHASHVALUE),
which motivated the prefix-family rule — a reminder that per-name enumeration
is fragile and prefix/structural rules generalize better (the Phase 2 lesson).

## 9. Open questions

- How are utlist/uthash actually vendored in target projects — as scanned
  headers (→ Phase 2 can expand them directly, shrinking the Phase-1 registry)
  or only transitively included (→ registry needed)? Phase 0 answers this.
- Do any current TPs depend on the *absence* of expansion (i.e. a real bug that
  only shows when the macro is opaque)? Must verify none before Phase 2.
- Interaction with conditional compilation (§3.7): which `#if` branch is "live"
  when a macro has multiple definitions? Out of scope for Phases 1–3.

---

## 10. Phase 3 stock-take (task 186, 2026-06-17)

The §1 / §5A figure of **"51 of 290 rule files (~18%) carry bespoke macro
logic"** is a *pre-Phase-1* count. Phases 1 (task 180) and 2c (task 185) already
did the substantive consolidation, and the original count conflated four
distinct categories that a Phase-3 migration must treat differently. A full
re-audit of every macro-touching rule `.rs` file (grep `preproc_|macro_|FOR_EACH|
FOREACH|function_macro|*_macro`, then per-file inspection) gives the real
disposition below. **Net: the only rule still carrying a genuine duplicate of
the shared expansion engine is ARR30-C.** Everything else is either already on
shared infra, legitimately definition-side, or incidental AST traversal.

### Disposition table

| Category | Rules | Disposition | Why |
|---|---|---|---|
| **Already on the engine** (`macro_expand` / `macro_semantics`) | EXP33, EXP34, MEM30, DCL31, MEM31 | done | Migrated in Phase 1 / 2c. MEM31-C added 2026-07-22 (task 2, v0.4.120): `frees_param_fields` in `function_summary.rs` now checks `macro_nulls_param_indices` before falling back to the `is_deallocation_call_name` name heuristic, so a macro-wrapped free (e.g. `mosquitto_FREE`, `Curl_safefree`) is credited by its actual free+null body shape, not by name pattern-matching. |
| **Engine duplicate — MIGRATE** | **ARR30** | **migrate** | Local `extract_function_macros` + dead-code `FunctionMacro` struct = a single-file reimplementation of `context.function_macros` (`macro_expand::FunctionMacro`). Its `check_macro_invocation` is *live* (~60 manual-review flags across the curl audit), so this is also a precision lever — cross-file context exposes header macros → must gate the flag count. |
| **`const_eval` consumers — DRY candidate** | INT30, INT32, INT33, INT34, FIO30, FLP03, STR02, ERR33, ENV03, ENV33, DCL07 | optional DRY | Already consume the shared `const_eval::collect_macro_constants` / `collect_macro_aliases` + `context.macro_constants` / `macro_aliases`. *Not opaque-macro debt.* They repeat a "collect-per-file + merge cross-file context, per-file wins" idiom (~10×) that could fold into one `const_eval` helper for consistency — mechanical, low-risk, modest payoff. |
| **Definition-side hygiene / naming / declaration rules — KEEP** | PRE00–13, PRE30–32, MSC38, MSC41, API10, API03, DCL37, EXP44, DCL19, DCL15 | keep | Audit macro *definitions* as written (reserved-name `#undef`/`#define`, `_Generic`, `static`-in-macro-prefix, multiple-eval hygiene). Per §3.8 these need the raw view; expansion would defeat their purpose. |
| **Incidental `preproc_` AST traversal — KEEP** | MSC13, MSC37, MSC07, DCL40, DCL30, SIG31, ARR01, ARR36, API00 | keep | Only skip/recurse `preproc_*` nodes during a normal AST walk (e.g. `kind().starts_with("preproc_")`). No macro semantics. |
| **Shared `is_likely_macro_constant` name heuristic — KEEP** | MEM05, ARR32, MEM33, DCL03 | keep | Uppercase-name guess ("is this an ALL_CAPS macro constant?"), not value extraction; does not duplicate `const_eval` (which resolves values). Text-heuristic family — see task 197, not the expansion engine. **Deduped in task 603** (v0.4.288): all four now call `ast_utils::is_likely_macro_constant`, previously reimplemented per-rule with divergent edge cases. EXP08-C's copy was unreachable dead code and was deleted (see task 618 for whether it should be made live). |

### Phase 3 execution plan (revised)

1. **ARR30 migration (the substantive piece).** Replace ARR30's private
   `extract_function_macros` + local `FunctionMacro` struct with
   `context.function_macros` (`set_project_context`, as MEM30/EXP33 already do).
   Note the shared `macro_expand::FunctionMacro` carries `{params, body}` only —
   no `name`/`line`; ARR30's "Macro defined at line N" suggestion must either
   drop the line or recover it from the invocation/definition site. Gate on
   Juliet recall (ARR30 ↔ CWE-121/122/787) **and** the curl/mosquitto ARR30
   manual-review flag delta (cross-file exposure can raise it).
2. **Optional const_eval DRY** (the 11 consumers above) — only if the ARR30
   gate is clean and the consistency payoff is judged worth the regression
   surface across INT/FIO/STR/ERR/ENV. Deferrable to its own task.
3. **Do NOT touch** the keep categories.

This re-scopes task 186 from "migrate ~51 files" to "migrate ARR30 + optional
const_eval DRY"; the bulk of the original estimate was already retired by
Phases 1/2c. Recall-gate per §8.

---

## 11. Phase 4 as built (task 187, 2026-08-27)

**Phase 4 shipped as compile-database *ingestion*, not as approach C.** §5(C)
scoped it as "shell out to `cpp`/`clang -E`, parse the expanded TU, back-map via
`#line`". That is not what was implemented, and the divergence is deliberate.

### Why the scope changed

Re-reading §5(C) against the code showed the expensive half of approach C buys
very little that sqc cannot already do:

- `prescan::resolve_includes` already resolves `#include` transitively against a
  caller-supplied search list, and already harvests `macro_constants`,
  `macro_aliases` and `function_macros` from every header it reaches.
- `macro_expand` already expands those `function_macros`, and is already wired
  into EXP33-C, EXP34-C, MEM30-C, MEM31-C and DCL31-C.

So the reason §5(B) says sqc "cannot expand macros from unscanned system
headers" was never a missing *engine* — it was that nothing ever told sqc where
those headers live. A compile database knows. Feeding it the search paths and
`-D` state reaches most of the Phase-4 payoff while avoiding every §5(C) con:
no subprocess, no 10–100× TU blowup, no `#line` back-mapping, no second raw
parse for the PRE-rules, and no per-rule regression surface — because **what
gets parsed does not change at all**.

### What `src/analyze/compile_commands.rs` does

`--compile-commands <FILE>` (opt-in; absent ⇒ byte-identical behavior, per the
§4 no-build-system constraint) reads the database and contributes:

| From the DB | Into | Via |
|---|---|---|
| `-I`, `-isystem`, `-iquote`, `-idirafter` (resolved against each entry's `directory`, deduped, first-seen order) | the existing `include_paths` list, appended after any explicit `-I` | `prescan::resolve_includes` |
| `-D` (minus anything `-U`'d anywhere in the DB) | `macro_constants` / `macro_aliases` / `function_macros` | rendered as real `#define` text, then run through the *existing* `const_eval` / `macro_expand` collectors |

Rendering `-D` flags back into `#define` directives rather than hand-populating
the context maps is the load-bearing choice: command-line macros get exactly the
same constant folding, alias resolution and function-like handling as macros
written in a header, with no second implementation of `#define` semantics to
keep in sync.

### Invariants

- **Gap-filling, never overriding.** `-D` macros merge with `or_insert`
  semantics *after* prescan and include resolution, so a real `#define` in real
  source always wins. A build flag can only supply a name the tree never
  defined — it can reveal a constant sqc previously treated as opaque, but can
  never change the meaning of one it already resolved.
- **Merged, not per-TU.** A compile DB is per-file; `resolve_includes` takes one
  global list. The union is an approximation that can only make *more* headers
  reachable.
- **Stale paths are surfaced, not swallowed.** A database records absolute paths
  from the host that built the project. `resolve_includes` skips unresolvable
  includes silently (correct for its normal job), so a database generated on
  another machine or in a container would otherwise degrade into an expensive
  no-op that still looks like it worked. `CompileDb::missing_include_paths`
  drives a CLI warning instead.

### Known gap (deliberate)

A compile database contains the flags a build *passes*, so it does **not**
contain the compiler's implicit system header directories. `<sys/queue.h>` —
the §5(D) motivating example — lives only in `/usr/include` and is therefore
still out of reach; the §5(D) registry remains the answer for it. Closing this
needs the compiler's default search list (`cc -E -Wp,-v -`), which is why
`CompileDb::compilers` records the compiler executables. Left as a follow-up:
it reintroduces a subprocess, and the project-header win should be measured on
its own first.

### Validation status

Unit + end-to-end tests in `src/analyze/compile_commands.rs` (flag parsing for
both the `command` and `arguments` forms, shell quoting, `-U`, function-like
`-D`, the no-override invariant, and a tempdir case proving an angle-bracket
include of a vendored header becomes reachable and contributes both a constant
and a function-like macro). Full lib suite green (3852 tests).

The §8 gate applies here with a twist: because this flag can only *add*
macro/header knowledge, it changes what existing rules resolve, which per
CLAUDE.md's delta-adjudication protocol means findings can move to
`(file, line)` pairs outside the `ground_truth` denominator. A compile-DB run
is a changed-rule delta, not a like-for-like comparison.

### Measured on the real-world corpus (2026-09-01, sqc 0.4.320 @742e92a6)

First end-to-end measurement, after generating a compile database for all 9
projects on the benchmark host (`playbooks/setup-compile-commands.yml`; all 10
databases, Juliet included, load with **no** `missing_include_paths` warning).
A/B pair on the same binary: `sqc-0.4.320-742e92a6` vs `…-cdb`.

**The flag is very nearly a no-op on this corpus: 62,035 → 61,981 findings
(−54, −0.09%), with scan times unchanged** (e.g. hostap 446.7s → 445.3s).
curl, libcrc, lua, raylib and sqlite did not move by a single finding.

Everything that moved, by rule, with its `ground_truth` verdict:

| project | Δ | rule | labeled |
|---|---:|---|---|
| hostap | −2 | EXP34-C | 2 FP |
| pureftpd | −39 | DCL31-C | 1 FP, 38 unlabeled |
| sel4 | −27 / −1 | INT34-C / INT33-C | 3 FP, 25 unlabeled |
| mosquitto | +1 | API00-C | 1 FP |
| sel4 | +16 | ARR30-C | 14 unlabeled |

Net over the labeled subset: −6 FP, +1 FP. **No TP moved in either
direction** — so nothing regressed, but the effect is far too small to justify
running the corpus with the flag by default.

**Delta-adjudicated 2026-09-01** (`data/precision_audit/sel4/`
`import_delta_compile_db_task623.csv`, 39 labels, source
`delta_compile_db_task623`). Applying each project's `scope_include` predicate
first, per CLAUDE.md, removed the largest raw chunk before any reading:
pure-ftpd's 38 DCL31-C removals are all in `src/ftpd.c`, and that oracle covers
only its six SQL-logging files (it was onboarded as a CWE-89 client oracle), so
they are out of scope rather than unlabeled. That left 39, all sel4 `src/**`,
all adjudicated **FP**:

- the 24 INT34-C + 1 INT33-C *removals* — shift amounts are `seL4_PageBits`=12,
  `seL4_PageTableBits`=12, `seL4_LargePageBits`=21, `seL4_HugePageBits`=30, all
  far below the operand width (and still so at x86-32's 22), and
  `CONFIG_WORD_SIZE`=64 is a nonzero constant. sqc warned only because the
  macro was opaque, which is precisely the FP class this flag exists to kill.
- the 14 ARR30-C *additions* — each indexes an array declared
  `[CONFIG_MAX_NUM_NODES]` by a CPU index bounded by construction
  (`CURRENT_CPU_INDEX()`, or a `core_id` carrying
  `assert(core_id < CONFIG_MAX_NUM_NODES)`), plus `ksDomSchedule[index]` whose
  caller range-checks against the array's own size.

With the delta labeled, the scored comparison is (run #211 plain vs #212 cdb):
precision **18.9% → 18.9%**, recall **95.0% → 95.0%** (10321/10864 both), and
per rule corpus-wide INT34-C 6 TP/217 FP → 6 TP/190 FP, INT33-C 337 → 336 FP,
ARR30-C 980 → 994 FP. Net −15 FP out of ~44,000, and **no TP lost**. The flag
is safe and directionally correct; it is simply not worth a default.

Why so small is worth knowing before investing further: 4 of the 9 benchmark
projects (sqlite, mosquitto, curl, hostap) already hand-feed `-I /usr/include`
and friends in `bench/realworld_runner.py`'s `CODEBASES`, and
`prescan_directories` already crosses project headers without any `-I` at all.
The database was largely telling sqc things it already knew.

**Caveat found in the sel4 numbers — a compile DB is one build configuration.**
sel4's database is configured `KernelPlatform=pc99 KernelArch=x86`, but every
finding it moved is in `src/arch/arm/` or `src/arch/riscv/`. The mechanism:
`-I <build>/gen_config` makes the x86 build's `gen_config/kernel/gen_config.h`
reachable, which defines `CONFIG_MAX_NUM_NODES 1`; sqc then folds
`static word_t mpidr_map[CONFIG_MAX_NUM_NODES]` in `arch/arm/machine/gic_v3.c`
to a one-element array and reports ARR30-C on indexing it. The values are
correct *for x86*, applied to source that would only ever compile under a
different configuration. This is the "merged, not scoped per-TU" approximation
in the module docs, but sharper than that phrasing suggests: on a multi-target
project the approximation crosses architectures, not just translation units.
It is not a reason to avoid the flag on single-target projects; it is a reason
not to read a multi-arch project's compile-DB delta as a straight improvement.
