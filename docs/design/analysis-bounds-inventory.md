# Inventory: where the analysis bounds its own work

**Status:** snapshot taken when ADR-0017 was adopted. Each entry names its
file and function; line numbers drift, so they are not given. Re-derive
before you rely on any one entry.

ADR-0017 says a bound that cuts an analysis short must be **reported**
(exit 3), unless its fallback is a **sound over-approximation**. Each bound
is classified below by what happens when it is hit:

- **reported**: the scan says so;
- **sound**: the fallback keeps findings conservative, e.g. widening to
  the type's range, or "not proven, so report";
- **silent**: it returns what it has, and a caller may read that as "no
  finding" or "proven safe".

Silent bounds are the follow-up work ADR-0017 names. Each becomes a sound
fallback or a reported bound.

Kinds:

- **a** recursion turned into an explicit stack;
- **b** depth cap;
- **c** fixpoint or worklist iteration cap;
- **d** size or count cap;
- **e** time limit.

## Scan level (ADR-0017)

| Where | Bound | Kind | On hit |
|---|---|---|---|
| `containment::checkpoint` | step budget, `--rule-step-limit` (50M) | d | reported |
| `containment::checkpoint` | `--rule-time-limit` (300 s), read every 4096 steps | e | reported |
| `containment::start_watchdog` | max(2× limit, limit + 60 s) | e | reported; ends the scan with exit 3 |
| `containment::Escalation` | 3 failing files | d | reported; the rule is abandoned |
| `analyze::WORKER_STACK_BYTES` | 16 MiB per analysis thread | a/b | a stack overflow aborts the process and cannot be contained |

## CFG and dataflow

| Where | Bound | Kind | On hit | Effect if hit |
|---|---|---|---|---|
| `cfg::CfgBuilder::process_statement` and its siblings | none: native recursion per nesting level, with a checkpoint per statement | – | stack, see above | – |
| `dataflow::compute_reaching_definitions` | blocks × (defs+1) + blocks | c | **reported** (`cap_reached`) | was silent: unvisited blocks read as "no reaching definition", so MSC13-C reported false positives |
| `null_state::run_null_state_worklist` | 500 × blocks | c | **reported** | was silent: missing state reads as not null, so EXP34-C missed findings |
| `init_state::analyze_init_states_with_statics` | 500 × blocks | c | **reported** | was silent: EXP33-C missed findings. Its `worklist.contains` is O(n) per push |

## Value ranges

| Where | Bound | Kind | On hit | Effect if hit |
|---|---|---|---|---|
| `value_range::analyze_value_ranges` | `VRA_BLOCK_LIMIT` = 150 blocks | d | silent: no ranges | **hit routinely**. Mostly lost suppressions, so extra findings in large functions |
| `value_range::analyze_value_ranges` | 500 × blocks iterations | c | **reported** | was silent: unconverged ranges can be too narrow, which is unsound and can suppress real INT/ARR findings |
| `value_range::maybe_widen` / `widen_typed` | widen after 3 visits | c | sound | – |
| `const_eval` `resolve_*_var_range` | 3 identifier hops | b | silent | unresolved range, either direction |

## Prescan and function summaries

| Where | Bound | Kind | On hit | Effect if hit |
|---|---|---|---|---|
| `prescan::collect_local_tainted_vars` | `MAX_LOCAL_TAINT_PASSES` = 4 | c | silent | **turns into a "clean" verdict for closed callees** that FIO30-C trusts: missed findings |
| `prescan::propagate_param_buffer_sizes` | `MAX_BUFFER_PROP_PASSES` = 6 | c | silent | deep forwarders leave buffer sizes unknown |
| `prescan::propagate_param_null_states` | `MAX_PROPAGATION_PASSES` = 64 | c | warns on stderr, but no exit 3 | either direction; the measured worst case is 19 passes |
| `function_summary::propagate_*` (18 cross-file passes: frees, taint, stores, closes, clears, returns_allocation, may_leave_null, …) | 10 passes, one call-graph hop per pass | c | silent | wrapper chains deeper than 10 lose the fact. Missed findings for taint, allocation, frees and may-leave-null; extra findings for frees, stores, closes and clears credit |
| `function_summary::macro_calls_taint_source` | 8 nested macros | b | silent | missed findings |
| `function_summary::writes_on_all_paths_capped` | depth 96 | b | sound (no write credit) | – |
| `function_summary::clean_paths` | depth 96 | b | silent ("claims nothing") | missed findings |
| `function_summary::compute_conditional_write_return_correlation` | 8 contexts | d | sound (no proof) | – |
| `out_param_nonnull::Walk::block` | 64 paths | d | sound | – |
| `noreturn::infer_terminating_definitions` | 4 rounds | c | silent | **also order-dependent**: it iterates a randomly seeded `HashMap` while updating it, so a chain of 5 or more terminating wrappers resolves or not from run to run. A determinism bug in its own right |
| `side_effects` SCC fixpoint, `tarjan_sccs` | none; monotone over a finite set | a | – | terminates |
| `side_effects` macro nesting | depth 4 | b | sound (opaque), except in lenient mode, where it reads nothing | lenient mode misses findings |
| `const_eval` macro constant and range resolution | 5 rounds | c | silent | unresolved constants and ranges, either direction |
| `const_eval` alias chains | 8 links | b | silent | renamed allocator/free chains go unseen |
| `check_macros` | `MAX_DEPTH` = 8 | b | sound | – |

## Macro expansion

| Where | Bound | Kind | On hit | Effect if hit |
|---|---|---|---|---|
| `macro_expand` `expand_named` / `rescan` / `released_param_indices` | `MAX_EXPAND_DEPTH` = 32 (checkpoint per rescan) | b | silent: partial expansion | constructs hidden from rules |
| `macro_expand::nested_builds` | 32 | d | sound for "all" consumers | – |
| `macro_expand::evaluation_at_depth` | `MAX_MACRO_FORWARDING` = 4 | b | silent | under-counts multiple evaluation (PRE31/PRE12) |

## Preprocessor, parse repair, includes

| Where | Bound | Kind | On hit | Effect if hit |
|---|---|---|---|---|
| `unknown_identifier_recovery::parse_with_recovery` | 8 reparses (checkpoint per pass) | c | silent: ERROR subtrees remain | missed findings in macro-heavy files. Only `--report-macro-gaps` shows it |
| `unknown_identifier_recovery` lookback | 4 tokens | d | silent | same as above |
| `paren_preproc_guard` | 64-line statement lookback | d | silent | misparse, either direction |
| `compile_commands` response files | depth 8 | b | silent: the file is dropped | lost `-D`/`-I`, either direction |
| `resolve_includes`, `IncludeClosure`, `concurrency_roots` | explicit queue and visited set | a | – | terminate |
| tree-sitter parse | no timeout set | – | – | relies on tree-sitter's own linear-time parse |

## Utility helpers

| Where | Bound | Kind | On hit |
|---|---|---|---|
| `guard_dominance::is_nonnull_by_exhaustive_case_guards` | 4 case variables | d | sound |
| `result_checks::tested_from` | 2 copy hops | b | sound |
| `signal_handlers::local_fn_ptr_targets` | depth 4 | b | silent: missed handler registrations (SIG rules) |
| `signal_handlers` forwarder discovery | 4 rounds | c | silent |

## Individual rules

Most rule-level bounds are ancestor walks or heuristic windows, depth 3 to
20, that stop looking for a guard. They are sound, because a guard not
found means the finding is reported. The silent ones that can miss
findings:

- EXP10-C `MAX_EXPR_DEPTH` = 256;
- DCL02-C `MAX_SCOPE_DEPTH` = 100;
- WIN05-C `MAX_WRAPPER_DEPTH` = 4;
- WIN00-C 4 flag-macro rounds;
- FIO30-C `MAX_TAINT_ITERATIONS` = 16;
- SIG30-C macro depth 8;
- ARR30-C alias-taint passes (4) and cast-alias passes (3);
- MEM33-C gives up on expressions over 200 characters;
- MEM35-C 10-ancestor walk;
- EXP03-C depth 20.

Two rules slice text by byte offset and can panic on non-ASCII source:
FIO17-C's 200-character window and ARR00-C's 50-character lookback. Under
ADR-0017 that is now a reported rule failure, and each is a bug to fix.

## No bound at all

Nothing found iterates without a bound in a way that could fail to
terminate. The unbounded fixpoints are monotone over finite sets, and the
graph walks keep visited sets. The real exposures are:

- unchecked native recursion: CFG construction, dataflow definition
  extraction and the prescan collectors, all relying on the 16 MiB stack;
- the three worklists whose termination rested on their caps (null state,
  init state, value ranges), now reported when hit.
