# Decision: Keep aurora-lint's Own CFG Builder, Don't Adopt substrate::cfg v1 (task 253)

**Status:** DECIDED, no swap. Re-evaluate only if the trigger in §3 occurs.

## 1. The question

`lang-parsing-substrate` (the shared crate also used for `substrate::query`
AST search, see [`internal-utility-layer-vs-lang_parsing_substrate`] memory)
shipped a CFG builder (`substrate::cfg::build_function_cfg`, v0.1.5+)
mirroring aurora-lint's own `BasicBlock`/`CfgEdge`/`FunctionCfg` types. Should aurora-lint
swap `src/analyze/cfg.rs`'s `build_function_cfg` for the substrate's?

## 2. Why not, right now

The substrate's own module doc (`lang_parsing_substrate/src/cfg.rs`) states
its v1 scope explicitly excludes, by design:

- `switch`/`match` decomposition (treated as one opaque statement)
- `goto`/labeled-statement edge wiring
- constant-condition dead-branch folding (explicitly deferred as
  "tools_sqc's `MacroConstantMap` is a C-preprocessor-specific concept")

aurora-lint's own `cfg.rs` implements all three, and they are load-bearing, not
theoretical:

- `process_switch` builds one block per `case`/`default` arm with proper
  `break`-target stacking (task 320's fix for switch-opaque handling).
- `goto`/label wiring (`pending_gotos`) connects real control flow that
  null-state and value-range analysis both depend on.
- `build_function_cfg_with_constants` folds `switch(CONST) { ... }` and
  `if (CONST)` branches using `MacroConstantMap` — used directly by
  `dataflow.rs`, `null_state.rs`, `value_range.rs`, `init_state.rs`, and
  CERT-C rules (MEM01-C, MSC13-C, EXP33-C, EXP34-C among the direct
  `build_function_cfg` callers; ~30 call sites total).

Adopting substrate's builder as-is would silently regress all three:
switch-heavy functions would collapse to a single block (undoing task
320), `goto`-based control flow would misroute, and macro-constant folding
(a real FP-reduction lever, see `docs/design/macro-expansion.md`) would
disappear. None of that is caught by a type-signature match — it would
have to be caught by a full re-run of the Juliet/real-world suites, and
even then only for constructs the suites happen to exercise.

Building a compat shim (a post-pass adding switch/goto/macro-folding on
top of substrate's CFG) is possible in principle, but is pure engineering
cost with zero net capability gain over what `cfg.rs` already does today —
unlike the `substrate::query` migration (tasks 252/254), which won real,
measured value (30.7% Juliet speedup, iterative vs. recursive traversal)
for the same swap. There is no equivalent win available here: the target
API is currently a strict subset of the source, not an improvement.

## 3. When to revisit

The substrate's own doc comment defers switch/goto/constant-folding
"until a second language needs it" — i.e., until some other consumer of
`substrate::cfg` (not aurora-lint) needs feature parity and funds building it
generically. If that happens, revisit: at that point building the
compat/parity layer once, in the substrate, and having aurora-lint adopt it
becomes a net deduplication win rather than pure cost. Until then, `cfg.rs`
stays aurora-lint's own, exactly as `alias-analysis` infra investment stays off the
table per [`ceiling-decision-alias-vs-realworld`] — this is the same kind
of "no measured real-world driver yet" call.
