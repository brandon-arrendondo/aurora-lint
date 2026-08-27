# Scoping + implementation: STR31-C relay-function resolution → FunctionSummary

**Status:** Done (task 506). Implemented in the same session as this doc,
after Phase 1-3 of `docs/design/str31c-arr00-migration-scoping.md` (tasks
503/504/505) closed the capability gap that made an earlier fold unsafe.

**Driver:** Task 506, filed by the `str31c-arr00-migration-scoping.md` Phase
4 write-up: `find_relay_call`/`resolve_relay_source_size` hand-rolled
same-file interprocedural "source relay" detection (`data =
someSource(data)`, Juliet flow variants 21/22) via a direct AST walk over
the callee's own body, while the cross-file case already went through
`FunctionSummary::produces_param_buffer_size` (a prescan summary keyed by
function name, populated project-wide). The task's own instruction was not
to fold these blindly — do the scoping pass first.

## What the scoping pass found

At the time task 492 wrote Phase 4, folding same-file into
`FunctionSummary` would have been a real regression: the same-file AST
branch called `self.find_buffer_size` — STR31-C's full size-resolution
dispatcher (define-constant → array-decl → strlen-alloc → fixed-alloc →
realloc → alloca) — while `compute_produces_param_buffer_size` in
`function_summary.rs` only tried `resolve_alloc_assigned_in_range` +
`memset_content_length_in_range`. A same-file relay function whose size
came from an array declaration or a strlen-indirect allocation would
resolve correctly today and silently stop resolving (recall loss) if
same-file relay lookup were redirected to the weaker summary.

That gap has since closed:

- Phase 2 (task 504) moved array-declaration size resolution to the shared,
  AST-based `array_size::resolve_declared_array_size` (with a real
  `MacroConstantMap`), which `find_buffer_size` now calls directly.
- Phase 3 (task 505) added `buffer_size::resolves_to_strlen_call`, which
  `find_buffer_size`'s `find_strlen_based_alloc_size` branch now calls.

So `find_buffer_size`'s remaining resolvers are all now backed by shared
`src/analyze` primitives rather than STR31-C-local regex — nothing left in
the same-file path had no cross-file equivalent to draw on.

## What changed

1. **`src/analyze/buffer_size.rs`**: added
   `resolve_strlen_based_alloc_size(var_name, lines, fn_start, fn_end)`,
   promoting STR31-C's `find_strlen_based_alloc_size` indirect-allocation
   logic (the `calloc(len+1, 1)` / `calloc(len+1, sizeof(char))` /
   `calloc(len+1, sizeof(wchar_t))` / `malloc(len+1)` forms, plus the direct
   `malloc(strlen(x)+1)` inline case) to a shared function. STR31-C's own
   `find_strlen_based_alloc_size` is now a one-line delegate to it — no
   behavior change for the same-file case, just de-duplication.
2. **`src/analyze/function_summary.rs`**: `compute_produces_param_buffer_size`
   / `produced_size_for_var` now also try `array_size::resolve_declared_array_size`
   (threaded a `&MacroConstantMap` through, already available in
   `analyze_function`) and the new `resolve_strlen_based_alloc_size`, in
   addition to the existing alloc/memset resolvers. This makes the
   project-wide `produces_param_buffer_size` summary exactly as capable as
   `find_buffer_size`'s same-file dispatch.
3. **`src/rules/cert_c/STR/STR31-C/str31_c.rs`**: `resolve_relay_source_size`
   dropped its entire same-file AST-walk branch (finding the callee
   `function_definition`, resolving its parameters, calling
   `self.find_buffer_size`/`memset_content_length_in_range`/one alias hop
   directly). It now unconditionally looks up `callee_name`/`arg_idx` in
   `self.produces_param_buffer_size`, which `set_project_context` already
   populates from `context.function_summaries` for every function in the
   project — same-file included, not just cross-file. `find_relay_call`
   (finding the callee name + argument index from the call site's own text)
   is unchanged; only what happens with that `(callee_name, arg_idx)` pair
   changed.

## Verification

- `cargo build --lib`, `cargo clippy --lib -- -D warnings`, `cargo fmt`: clean.
- `cargo test --package sqc --lib`: 3793 passed, 0 failed, 12 ignored
  (unchanged from baseline) — includes all 59 STR31-C generated tests
  (Juliet-style + CERT-wiki fixtures), covering the relay-pattern flow
  variants this change touches.
- Real-world benchmark run required per CLAUDE.md protocol item 6 before
  citing any precision/recall claim for this change — see the task note on
  task 506 for the run id and result once complete.

## Residual scope not touched by this change

- `resolve_relay_source_size`'s one-alias-hop limit inside a relay function
  (`char *buf = malloc(...); char *buf2 = buf; data = buf2;` — two hops —
  still resolves as unbounded/unresolvable) is unchanged; it was already
  flagged as a latent, conservative-direction limitation in
  `str31c-arr00-migration-scoping.md` §6 and is out of scope here.
- `find_global_buffer_size` (whole-program global-buffer-size join, task
  507) is a separate Phase 4 item, untouched by this change.
