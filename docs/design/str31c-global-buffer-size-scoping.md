# Scoping + implementation: STR31-C `find_global_buffer_size` (task 507)

**Status:** Done. Implemented in the same session as this doc.

**Driver:** Task 507, filed by `str31c-arr00-migration-scoping.md`'s Phase 4
write-up as "AST-based whole-program global-buffer-size join... closest
analog: `ProjectContext::global_var_null_states`."

## What the scoping pass found

The "whole-program join modeled after `global_var_null_states`" framing
does not actually fit this case. `global_var_null_states`'s collector
(`collect_prescan_pointer_globals`) deliberately **excludes** `static` and
`extern` globals — it only tracks externally-linked globals, because those
are the only ones a genuine cross-file join makes sense for.

STR31-C's own caller comment (`find_buffer_size_with_alias`, right where
`find_global_buffer_size` is invoked) says the opposite: the pattern this
exists for — Juliet flow variant 45 — is specifically a **file-scope
`static` global** (`bad()` allocates and stores into a `static` global;
`badSink()` in the *same file* reads it). By C semantics a `static`
global's writers can only ever live in the same translation unit, so there
is no cross-file case to join for the pattern this function actually
serves. A whole-program collector built the `global_var_null_states` way
(non-static/extern only) would not even see the global this code targets —
it would be solving a different, unobserved problem instead of the one
`find_global_buffer_size` exists for. No evidence in the STR31-C real-world
FP/FN history points to a genuinely cross-file non-static-global relay
pattern being a live driver, either — the task's own priority note calls
the impact "narrower... Juliet-variant-45-style patterns specifically."

So the "whole-program join" half of the task title doesn't apply. The
"AST-based" half does: `find_global_buffer_size` still found its
assignment sites via a `source.lines()` regex scan (`\bGLOBAL\s*=\s*(?:\(
...\))?(\w+)\s*;`), even though the resolution of each site's RHS size
already goes through `find_buffer_size`'s AST-based dispatch chain.

## What changed

`find_global_buffer_size`'s line-regex scan for `global_name = target;`
assignment sites was replaced with an AST walk
(`find_global_assignment_targets` / `collect_global_assignment_targets`)
over `assignment_expression` nodes, mirroring the same pattern
`null_state.rs`'s `scan_body_for_global_assignments` already uses for the
analogous null-state collection. Behavior is preserved exactly for the
patterns the regex matched (bare-identifier RHS, one optional
parenthesized cast, MIN-across-sites join, same early-return-via-`?`
control flow on the first unresolvable site) — this is a pure
representation swap, not a resolver change.

Two narrow correctness improvements fall out as a side effect of checking
real AST fields instead of `\b`-delimited text:

- `left.kind() == "identifier"` (not just text matching `global_name`)
  means a struct/union field write that merely shares the global's
  spelling (`s->global_name = target;`) can no longer be mistaken for a
  write to the global — the old regex's `\bglobal_name\b` had no way to
  tell `s->global_name` from a bare `global_name` reference.
- Checking the assignment node's `operator` field is exactly `"="` (not
  just checking a literal `=` character survives regex backtracking)
  correctly excludes compound assignments (`global_name += x;`) the same
  way the old pattern did, but via a real grammar field instead of
  incidental regex behavior.

Both are strictly narrowing (fewer, more correct candidate sites feed the
MIN join), so the only possible effect is a *larger* resolved minimum size
(fewer false "writer" sites lowering it) or, if a global happened to have
no other real writers at all, `None` where a spurious match previously
supplied a value — never a smaller/wrong size. Neither case was observed
in the benchmark (see Verification).

## Verification

- `cargo build --lib`, `cargo clippy --lib -- -D warnings`, `cargo fmt`: clean.
- `cargo test --package sqc --lib`: 3793 passed, 0 failed, 12 ignored —
  unchanged from baseline, including all 59 STR31-C generated tests.
- Real-world benchmark (sqc-only, 9 codebases) run before/after — see task
  507 for the run ids and result.

## Residual scope not touched by this change

- The early-return-via-`?` on the first unresolvable writer site (a single
  writer this function can't resolve makes the whole call return `None`,
  discarding any smaller sizes already found from earlier sites) is a
  pre-existing behavior, unchanged here to keep this a pure AST-migration
  with no resolution-logic changes. Worth a future look if real-world audits
  ever show it suppressing a legitimate finding, but out of scope for task
  507.
- True cross-file relay through a non-static (externally-linked) global is
  still unhandled — no evidence found that it's a real driver; not filed as
  a follow-up without such evidence.
