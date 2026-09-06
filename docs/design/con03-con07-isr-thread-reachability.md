# CON03-C/CON07-C: ISR/thread/signal reachability (task 608 scoping)

**Status:** SCOPED, NOT IMPLEMENTED (2026-08-27). Task 608's own "Option B"
follow-on of `concurrency-rule-evaluation.md` §4 item 5, gated on task 607
(done — see that task's precision-split numbers below) and on
`lang-parsing-substrate` shipping real ISR detection (done — v0.7.0, this
repo's `Cargo.toml` bumped in commit `3ff7320a`; see
`lang_parsing_substrate/ISR_DETECTION.md` for that primitive's own design
handoff). This doc is the design; implementation is separate follow-on work,
consistent with task 151/606/607/608's own established pattern of
scoping-before-building.

## Goal

CON03-C and CON07-C currently fire with **zero check on whether the flagged
code is ever reachable from a second thread, ISR, or signal handler** —
confirmed by reading `con03_c.rs`/`con07_c.rs` directly (no `isr`/`thread`/
`signal_handler` logic exists in either). Task 607's retroactive re-score of
76 real-world-adjudicated CON03/07/33/34/37-C findings, using a crude
same-file regex proxy for concurrency-context evidence, found:

| Bucket | Precision | TP | FP |
|---|---|---|---|
| Context present | 26.3% | 5 | 14 |
| Context absent | 1.8% | 1 | 56 |

Goal: replace CON03-C's/CON07-C's unconditional firing with a gate — only
report a finding when the flagged variable/function is actually
**call-graph-reachable from a real concurrent-execution root** (an ISR, a
spawned-thread entry point, or a registered signal handler) — expected to
suppress the bulk of the 56 context-absent FPs while preserving the known TPs
(enumerated below, used as the implementation's regression set).

## Non-goals for v1 — explicit, not oversights

- **CON33-C is out of scope.** Task 608's own title names only
  CON03-C/CON07-C. CON33-C's problem (fires on a fixed non-reentrant-function
  name list with zero context check) is the same *class* of gap and could
  reuse this same infrastructure later, but extending it is a separate task.
- **AVR-libc `ISR(vector) { ... }` macro handlers cannot seed the root set.**
  `InterruptEvidence::MacroInvocation` handlers have `name: None` — the
  grammar has no macro expansion, so there is no real function-name node to
  resolve (see `ISR_DETECTION.md`). Worse: `src/analyze/prescan.rs`'s
  `collect_call_graph` wraps `lang_parsing_substrate::calls::call_edges`,
  which itself excludes macro-shaped function definitions via
  `is_macro_function_definition` (see that crate's calls.rs and
  `ISR_DETECTION.md`'s "Cross-cutting note") — so these handlers are not
  even nodes in `ProjectContext::call_graph` today. This only matters for
  AVR/embedded-style codebases; none of this repo's real-world benchmark
  projects (sqlite/curl/mosquitto/hostap/lua/raylib/pureftpd/sel4/libcrc) are
  AVR firmware, so it shouldn't affect the measured precision numbers this
  task cares about. Flagged, not fixed here.
- **`sigaction()`'s struct-field registration form is deferred.** Checked the
  one real-world codebase with actual CON03-C signal-handler TPs (mosquitto,
  see below): it registers exclusively via plain `signal(SIG, handler)`
  (`~/toolchain/mosquitto/src/signals.c:76-87`), not `sigaction()`. v1 scopes
  root detection to `signal()`'s direct 2-argument form only, on this
  concrete evidence, not a guess. `sigaction()`'s `act.sa_handler = fn;`
  field-assignment form (or a designated initializer) is a documented gap for
  a later pass if real-world evidence ever needs it.
- **Not true race-pair detection.** A sound race check would require the
  flagged variable to be touched from *two* independent, non-mutually-exclusive
  execution paths (e.g. both `main()` directly *and* a spawned thread).
  Simple forward-reachability-from-a-root, which is what's scoped here,
  can't see that main()-vs-thread shape — it only asks "is *this* access ever
  reachable from a concurrent root at all," which is a coarser, cheaper gate.
  This matches task 151's own original "Option B" framing exactly ("give
  CON03-C/CON07-C real reachability analysis so they only fire when the
  flagged variable is actually reachable from a registered ISR or a second
  thread") — not a scope reduction introduced here, just made explicit.
- **Scan-scope-bounded, not whole-project-bounded.** Reachability is computed
  over `ProjectContext::call_graph`, which is only as complete as the `-d`
  prescan's directory tree. Without `-d`, this is empty (see the capability
  catalog's standing caveat) and the gate degrades to single-file recall —
  same limitation every other cross-file-context rule already has.

## Known TPs — the regression set

Any implementation **must** re-verify these still fire after the change
(pulled from `data/precision_audit/mosquitto/import_delta_batchD_task547.csv`,
the only real-world project with confirmed CON03-C TPs in the labeled
corpus):

| File:line | Variable | Why it's a real race |
|---|---|---|
| `lib/net_mosq.c:87` | `is_tls_initialized` | One-time-init guard, read/written in `net__init_tls()`/`net__cleanup()`, reachable from `net__init_ssl_ctx()` — invoked per-connection by each libmosquitto client's own loop thread (spawned via `mosquitto_loop_start` → `thread_mosq.c`). |
| `src/signals.c:36` | `flag_reload` | Set in `handle_signal()` (SIGHUP), polled in the main loop, not `volatile sig_atomic_t`. |
| `src/signals.c:37` | `flag_log_rotate` | Same pattern, SIGRTMIN. |
| `src/signals.c:39` | `flag_db_backup` | Same pattern, SIGUSR1. |
| `src/signals.c:41`/`:42` | `flag_tree_print`/`flag_xtreport` | Same pattern, SIGUSR2. |

## A real macro-forwarding trap in the flagship TP — must resolve, not skip

`net_mosq.c:87`'s TP is the one genuine thread-spawn case in the regression
set — and it does **not** call `pthread_create` directly. Checked
`~/toolchain/mosquitto/lib/thread_mosq.c:51`:

```c
if(!COMPAT_pthread_create(&mosq->thread_id, NULL, mosquitto__thread_main, mosq)){
```

`COMPAT_pthread_create` is a function-like macro
(`~/toolchain/mosquitto/lib/pthread_compat.h:7`):

```c
#  define COMPAT_pthread_create(A, B, C, D) pthread_create((A), (B), (C), (D))
```

A thread-root detector that only matches a literal `call_expression` whose
`function` field's text is exactly `pthread_create`/`thrd_create`/
`CreateThread` **would miss this call entirely** — turning the one real
thread-spawn TP in the current labeled corpus into a silent false negative.
This is exactly the class of bug CLAUDE.md's macro-expansion guidance exists
for ("check whether `src/analyze/macro_expand.rs` already solves it — do NOT
reach for a name-heuristic workaround first"), and it does:

- `ProjectContext::function_macros: HashMap<String, FunctionMacro>`
  (`src/analyze/context.rs`, cross-file, already populated during prescan)
  would have `COMPAT_pthread_create` in it.
- `macro_expand::expand_invocation(table, name, args) -> Option<String>`
  (`src/analyze/macro_expand.rs:300`) takes the macro name plus the actual
  call-site argument texts and returns the substituted expansion — calling
  it with `("COMPAT_pthread_create", ["&mosq->thread_id", "NULL",
  "mosquitto__thread_main", "mosq"])` returns the literal text
  `"pthread_create((&mosq->thread_id), (NULL), (mosquitto__thread_main),
  (mosq))"`. Already used by a rule today (`ARR30-C`) — real precedent, not
  a hypothetical API.
- The expanded text can then be scanned the same way a literal
  `pthread_create(...)` call site would be, using the same top-level
  comma-splitting logic already private in that file
  (`parse_call_args`, `src/analyze/macro_expand.rs:448` — handles nested
  parens/quotes correctly; would need `pub(crate)` visibility or an
  equivalent to reuse from the new root-detection code, or from wherever it
  ends up living).

**Required detection shape, not just the direct-call case:** for every
`call_expression`, check the direct callee name against the known
thread-spawn API list first; if it doesn't match, look the callee name up in
`ProjectContext::function_macros`, expand it with the actual argument texts,
and check whether the *expansion* contains one of the known APIs — extracting
the corresponding real argument (the thread-entry function name) from the
expanded text at that point. Skipping this step silently breaks the one
concrete thread-spawn TP this task set out to preserve.

## Architecture

### 1. Root-set collection (three sources, per-file, merged like other prescan fields)

```rust
fn collect_concurrency_roots(root: &Node, source: &str, out: &mut HashSet<String>) {
    // (a) ISR handlers with a resolvable name.
    for h in lang_parsing_substrate::interrupt_handlers(*root, source) {
        if let Some(name) = h.name {
            out.insert(name);
        }
    }
    // (b) Thread-spawn entry points: pthread_create/thrd_create/CreateThread,
    //     direct or macro-forwarded (see section above) -- extract the
    //     start-routine argument (3rd/2nd/3rd positionally) as an identifier.
    // (c) Signal handlers: signal(SIG, handler) -- extract the 2nd argument.
}
```

Signatures for (b)/(c) mirror the existing `collect_call_graph`/
`collect_ambiguous_call_targets` shape in `prescan.rs` (same file, same
per-file → merge-across-files pattern already used for `call_graph`,
`ambiguous_call_targets`, `global_writers`, etc.).

**Argument-extraction edge case:** handle both a bare identifier
(`mosquitto__thread_main`) and an address-of'd identifier (`&worker`) for the
start-routine argument — some codebases write it either way; C decays a
function name to a pointer without `&`, but `&fn` is also legal and appears
in the wild. `src/analyze/points_to.rs` or the existing `is_address_of`-style
helpers used by the ARR37-C fix (task 556) are the precedent to check first
rather than re-deriving.

### 2. Storage — new `ProjectContext` field

Add `concurrency_reachable: HashSet<String>` to `src/analyze/context.rs`,
computed once during prescan (`prescan.rs`, alongside `collect_call_graph`):

1. Collect the root set (step 1) across every prescanned file, merged — same
   pattern as `ambiguous_call_targets`.
2. Strip `ambiguous_call_targets` from `call_graph` first — **reuse
   `Msc04C::strip_ambiguous_callees`'s exact logic** (`src/rules/cert_c/MSC/
   MSC04-C/msc04_c.rs:41-60`; currently private/rule-local — promote to a
   shared helper, e.g. in `prescan.rs` or a small new module, rather than
   duplicating the filter). Task 562's MSC04-C fix exists precisely because
   name-matched indirect-call edges (`obj->cb(...)`, parameter-shadowed
   identifiers) fabricate call-graph edges that aren't real — the same
   fabrication risk applies to a reachability BFS, not just MSC04-C's cycle
   detection.
3. Forward BFS/DFS from every root name over the stripped graph, collecting
   every reached function name (including the roots themselves) into
   `concurrency_reachable`.

Precomputing this once and sharing it between CON03-C and CON07-C (rather
than each rule running its own BFS) matches how `function_summaries`,
`global_writers`, etc. are already shared computed-once fields.

**Single-file fallback (no `-d`):** per the standing wiring pattern
(capability catalog, "OR'd with a same-file-only check"), CON03-C/CON07-C's
own `check()` (which runs even without a prescan) should independently run
the same root-collection + local-file-only BFS over whatever `call_graph`
info is derivable from the single file being scanned, then OR that
same-file result with `ProjectContext::concurrency_reachable` when
`set_project_context` has populated it. Reduced recall without `-d`,
consistent with every other cross-file-context rule.

### 3. Rule wiring

**CON07-C** — already function-scoped (`check_function_for_non_atomic_operations`
already resolves `func_name` via `cfg::get_function_name` and reports at
`function_node.start_position()`, `con07_c.rs:193-274`). Gate is a single
membership check: skip the function entirely (return early, same place the
existing `uses_mutex_lock`/`init`-name skips already happen) unless
`func_name` is in the reachable set.

**CON03-C** — harder: it reports at the **declaration site** of the shared
variable (`decl_node.start_position()`, `con03_c.rs:171-179`), not at an
access site, and a single global/static variable can be touched from many
functions. There is currently no "which functions read/write this variable"
collector anywhere in CON03-C. New work needed:

```rust
fn collect_accessing_functions(root: &Node, var_name: &str, source: &str) -> HashSet<String>
```

Walk every `function_definition`, find `identifier` references to
`var_name` in the body (excluding the declaration itself), record the
enclosing function's name (`cfg::get_function_name`, consistent with
CON07-C's existing usage). Gate: keep the violation only if **any** accessing
function is in `concurrency_reachable` — matching real semantics (the
variable could be raced from that function even if the *declaration* line
itself is never "reached" in any call-graph sense; declarations aren't call
targets).

### 4. Validation plan

`~/toolchain` is already provisioned (task 607's ansible run) with all
real-world benchmark checkouts pinned at their oracle commits, so validation
doesn't need the benchmark node:

1. Implement, build, `cargo test` (add fixtures per the usual
   `tests/pass`/`tests/fail` convention — CON03-C/CON07-C likely already have
   some; check before assuming none exist, per the STR34-C lesson from task
   574 where fixtures existed but weren't found by a naive filename grep).
2. Run `aurora-lint` directly against `~/toolchain/{mosquitto,curl,sqlite,hostap,
   lua,raylib}` with `-d` before/after, diff CON03-C/CON07-C finding counts
   and exact `file:line`s.
3. **Hard requirement, not optional:** confirm all 6 known TPs in the table
   above are still flagged after the change (this is the real test of the
   macro-forwarding fix above, not the aggregate count).
4. Confirm the FP mass in context-absent files (mosquitto's broker
   `src/*.c` — no `pthread_create` anywhere per task-546's existing
   writeup) drops to near-zero.
5. Per CLAUDE.md's delta-adjudication protocol: this changes CON03-C/CON07-C's
   detection logic, so any *new* findings this surfaces at previously-silent
   lines land outside the existing `ground_truth` labels and must be
   delta-adjudicated before citing a precision number — though since this
   change is a pure **suppression** (existing findings dropped, no new ones
   added at new lines), that risk is much lower here than for a rule that
   changes what it flags. Still worth an explicit `bench realworld-unlabeled`
   sanity check for zero-new-lines once a real benchmark run exists.

## Rough effort framing (for the task-150 gate)

Most of the hard infrastructure already exists and is proven:
`ProjectContext::call_graph` (already substrate-backed via `call_edges`),
`ambiguous_call_targets` + its stripping pattern (MSC04-C, task 562, already
shipped), the ISR-detection primitive (substrate 0.7.0, already shipped and
tested). Net-new work is: a thread/signal root collector (with the
macro-forwarding resolution above — the one genuinely non-trivial piece), a
plain forward-BFS (much simpler than MSC04-C's cycle-detection DFS), a new
`ProjectContext` field + prescan wiring (mechanical, several existing
examples to copy), CON07-C's one-line gate, and CON03-C's new
accessing-functions collector. This reads as a moderate addition built almost
entirely from existing, already-validated primitives — not the kind of
from-scratch infrastructure bet task-150's standing guidance is warning
against — but the call is the user's to make.
