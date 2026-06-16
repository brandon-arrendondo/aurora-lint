# Scoping: Macro Expansion in sqc

**Status:** Scoping / design (2026-06-16). No implementation yet.
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
  layout → bump a cache-format version and invalidate stale caches (the
  `rebuild_prescan` path already exists). The registry (Phase 1) remains the
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
