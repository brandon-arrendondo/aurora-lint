# Rule Architecture Sweep: What Can This Tool's Current Architecture Actually Support? (task 1434)

**Status:** First-pass complete. This doc produces a *map* — per Brandon's
ruling on task 1419, no rule is dropped, disabled, or rearchitected as part
of this sweep itself; every disposition below becomes its own scoped
follow-up task, with its own justification, when someone picks it up.

## 1. Motivation

Task 1419 found that EXP33-C's `check_cross_file_uninit_calls` was wrong in
essentially every sampled real-world instance — not through one bug, but
through three independent mechanisms (see
`docs/design/exp33-c-cross-file-uninit-architecture.md`). Brandon's ruling:
whether to drop, patch, or rearchitect a CERT-C rule is never a call one
node's sample settles, and deserves the same deliberate treatment across the
whole rule set, not just the one rule that happened to get sampled first.
This task is that sweep: a systematic, per-rule disposition into one of four
buckets —

- **(A) Sound** — current infrastructure can express the rule's true
  condition.
- **(B) Limited but fixable** — a concrete gap exists, closable with
  infrastructure this project already has (a known pattern, a shared
  primitive, a filter EXP33-C already built for the same underlying fact).
- **(C) Needs genuine rearchitecture** — the gap needs a capability this
  project does not have (e.g. real points-to/alias analysis), and the doc
  scopes what that would cost.
- **(D) Not decidable at this tool's target precision** — ADR-0001's "must
  be tool-provable" cuts both ways: a condition this tool cannot prove
  statically should be a documented limitation, not a best-effort guess.

## 2. Method

aurora-lint implements 311 CERT-C rules. Reading all 311 bodies by hand in
one pass is not a sweep, it's a rewrite. So this pass uses a **mechanical
triage signal** to find the rules structurally similar to EXP33-C's own
failure mode, then reads those closely — the same discipline EXP33-C's own
audit used (trace the real callee, don't trust the hypothesis), applied at
the rule-family level instead of one rule at a time.

The signal: EXP33-C's bug was specifically about **cross-file interprocedural
propagation** — a fact computed once about a callee's body during prescan
(`FunctionSummary`) and trusted by every caller, unable to see through
indirection, without a MAY/MUST discipline, or without a text heuristic
misfiring on the callee's own source. So:

1. **Does the rule consume `context.function_summaries` at all?** A rule
   that doesn't isn't exposed to this specific failure class — it may still
   have other bugs (that's ADR-0005's standing policy, not this sweep's
   question), but it isn't a candidate for "the EXP33-C problem."
   311 rules total; **22 do** (`grep -lr function_summaries
   src/rules/cert_c --include=*.rs`), grouped below by which field family
   they read.
2. **Which specific field(s)?** Different fields carry different proof
   strength (`modifies_params` is a MAY fact; `unconditional_modifies_params`
   is a MUST fact; `conditional_write_return_correlation` is a proof, absent
   meaning unproven — never "false"). The field tells you which failure mode
   is even possible.
3. **MAY-for-suppression vs. MAY-for-assertion.** A MAY fact used only to
   *stop* a report (WIN05-C, API00-C, MEM03-C below) is safe by
   construction — worst case it's silently over-conservative. A MAY-strength
   (or otherwise incomplete) fact used to *assert* a violation or safety
   claim is where every confirmed bug this session and in project history
   lives: EXP33-C's old `dereferences_params.difference(&modifies_params)`,
   ENV03-C's `has_env03_taint_source` (found this pass), and EXP34-C's
   `null_state.rs` consumer (found this pass) all share this exact shape.
4. **Does the fact account for an unresolvable indirect call** the way
   `forwards_to_indirect_call` does for EXP33-C, or does it silently drop or
   silently credit across a function-pointer/struct-of-ops dispatch?
5. **Prior git history on the computing function**, as a proxy (not proof)
   for how much scrutiny it has already had: a thin, single-origin
   implementation with zero follow-on fixes means *unaudited*, not *sound*.
   A string of narrow patches over time (MEM31-C's `frees_params_guessed`,
   tasks 1367/1269/1289/401) means *known-limited and actively maintained*,
   a different and generally safer place to be than *unaudited*.

Every entry below states which of these signals it rests on, and whether it
was independently traced this pass or is read from an existing
`docs/design/*.md`. Per CLAUDE.md's own warning, a design doc's "Status"
header goes stale once work ships faster than the header is updated — several
of the existing docs cited below have exactly this problem, noted explicitly
rather than trusted at face value.

## 3. Worked example: EXP33-C

Full detail in `docs/design/exp33-c-cross-file-uninit-architecture.md`,
which this sweep treats as already complete and does not repeat. Summary: a
single "read-only classification is wrong" symptom decomposed into three
independent mechanisms (a text misfire, an indirection gap, and a separate
InitState tracking bug), three of four proposed increments landed as their
own tasks (1437, 1442, 1444, plus a fourth gap found and split off as 1450),
one increment (concrete indirect-target resolution) explicitly declined
against the same "no measured driver" precedent
`docs/design/cfg-substrate-adoption-decision.md` already set. Combined
measured local delta: 1489 → 1444 findings (-3.0%, this checkout's own
record — official measurement still owed to a VLAN30-capable node's A/B +
delta-adjudication).

The two lessons this sweep carries forward from that doc's own §6: (1) a
symptom that looks like one architecture problem is often two or three
independent ones, decompose before committing to a rearchitecture; (2) a
design doc's own hypothesis about *why* a case fails needs re-verification
against the real callee every time, including when the hypothesis is the
doc's own — both (b) and 1450 found the actual mechanism was different from
what the doc originally guessed.

## 4. Tier 1: the 22 rules with direct cross-file `FunctionSummary` exposure

### 4.1 Write / free / pass-through propagation family

The family EXP33-C itself belongs to — `modifies_params`,
`conditional_modifies_params`, `unconditional_modifies_params`,
`frees_params`, `frees_params_guessed`, `clears_params`,
`param_passthroughs`.

| Rule | Field(s) | Bucket | Rationale |
|---|---|---|---|
| EXP33-C | `modifies_params` family, `forwards_to_indirect_call`, `conditional_write_return_correlation` | **A (now)** | Done — see §3. |
| MEM31-C | `frees_params`, `frees_params_guessed`, `frees_param_fields`, `modifies_params` | **A** | Actively maintained MAY/guessed-vs-proven split (`frees_params_guessed` kept apart from real evidence, `requires_manual_review` flagging for MEM30-C — see the field's own doc comment in `function_summary.rs`); 4+ historical fix commits (tasks 1367, 1269, 1289, 401), most recently task 1367 this project's history (a deallocator that frees through a function pointer still frees). Read this pass via git history + doc comments, not a fresh trace. |
| MEM03-C | `clears_params` | **A** | MAY fact used only to *recognize* a clearing call (suppression direction), own transitive propagation, own hardening tests (task 1127, volatile-pointer/preprocessor-arm cases). Traced this pass (fork); no indirect-call gap found. |
| WIN05-C | `param_passthroughs` | **A** | MAY-forward *by design*, with an explicit doc comment reasoning about the direction ("a wrapper that opens the key only on some path still opens it," `win05_c.rs:102-104`) — the MAY/MUST choice was deliberate, not defaulted into. Traced this pass. |
| **MEM01-C** | `dereferences_params`, `modifies_params` | **B — concrete gap, cheap fix** | `build_read_only_params` (`mem01_c.rs:53-67`) is a byte-for-byte copy of EXP33-C's **pre-fix** `build_read_only_deref_fns`: no `modifies_params_pending` exclusion (piece a), no `forwards_to_indirect_call` exclusion (piece b). It silently inherited the *population*-side fix (task 1444's `has_genuine_arrow_read`, same shared field) but never got the *consumption*-side fixes. Concretely: a callee reached only through an unresolvable driver-ops dispatch, or with an undischarged forwarding obligation, is still misclassified read-only, so MEM01-C asserts "genuine read of a possibly-freed pointer" on a call that may reassign it — a direct false positive, same shape hostap's `accounting_sta_update_stats` was for EXP33-C. **Fix is a direct port of EXP33-C pieces (a)+(b)'s two filters into this one function** — no new capability needed. |
| **EXP34-C** (via `null_state.rs`) | `modifies_params` | **B — concrete gap, shared infra, higher priority** | EXP34-C itself only *synthesizes* summary entries for macros; the actual consumer is `null_state.rs::apply_cross_file_output_params_null` (`null_state.rs:620-656`), which marks a `&var` argument `NotNull` whenever `summary.modifies_params.contains(&arg_idx)` — the raw MAY set, not `unconditional_modifies_params`. CERT's own canonical EXP33-C example (`set_flag(n, &sign)`, writes only when `n != 0`) gets the caller's variable marked definitely-non-null even on the no-write path. **This is generic `NullState` dataflow infrastructure, not EXP34-C-specific** — the blast radius is every rule reading null state after such a call, and the direction is a **false negative** (a real null-deref silently marked safe), the opposite direction from — and arguably more serious than — EXP33-C's original FP-shaped bug. Fix shape is the same as piece (a): swap to `unconditional_modifies_params` (or subtract `conditional_modifies_params`) in `apply_cross_file_output_params_null`. |
| MEM30-C | `conditional_modifies_params`, `frees_params_guessed`, `unconditional_frees_params` | **Not individually traced this pass** | Adjacent to MEM31-C's hardened mechanism (shares two of its three fields) but not itself read closely. Flag for a follow-up trace before assuming MEM31-C's maturity transfers — field-sharing isn't proof of identical consumption discipline (MEM01-C shares `modifies_params` with EXP33-C and did NOT inherit the consumption-side fix). |

### 4.2 Taint propagation family

`has_env03_taint_source`, `returns_tainted`, `returns_only_compile_time_constants`.

| Rule(s) | Bucket | Rationale |
|---|---|---|
| ENV03-C, ENV33-C, INT30-C, INT31-C, INT32-C, STR02-C, INT34-C | **B — concrete gap, unaudited family, no existing doc** | `has_env03_taint_source` (`function_summary.rs:1110-1116`) is computed by a **raw substring scan** (`body_text.contains("getenv(")` against a hardcoded ~30-name list) with no comment-stripping and no string-literal exclusion — unlike the neighboring `returns_allocation` computation three lines up, which does call `strip_comments_multiline` first. This is the exact ADR-0005/ADR-0006 misfire shape fixed twice this session for EXP33-C (`cast_then_deref`, `has_genuine_arrow_read`): a comment `// TODO: call getenv(x) here` or a string literal containing `"getenv("` sets the bit. Consumption is **MUST-style, not suppression-only** (`env03_c.rs:385,662,1032` gate "this caller is clean" on `!has_env03_taint_source`), so the misfire is a genuine false-positive path, not a safe-direction over-conservatism. 5 prior commits touched this mechanism (hardening for macro aliases and function-pointer alias resolution), so it has had *some* attention, but never the comment/string-literal-stripping treatment the write-propagation side got. **Fix is the same class already proven this session** (`strip_comments_multiline` + literal exclusion), scoped as its own follow-up. No dedicated design doc exists for this family. |
| FIO30-C | **Grouped with the above, not individually traced** | Consumes `callsite_param_taint_observed`/`callsite_param_tainted`, the same taint family from a different angle (format-string argument taint rather than injection-sink taint). Scope into the same follow-up task rather than a separate one. |

### 4.3 Buffer-size / over-read family

`callsite_param_field_buffer_size`, `distinct_object_param_pairs`,
`callsite_param_buffer_size`, `produces_param_buffer_size`.

| Rule(s) | Bucket | Rationale |
|---|---|---|
| ARR30-C, ARR38-C | **B, scoped, partially landed** | `docs/design/arr30-arr38-buffer-size-scoping.md`. Header says "migration NOT started"; the doc's own dated §8 status table shows 8 of 9 follow-up items already closed (several changing real detections) — **the top header is stale, trust the dated body section**, consistent with CLAUDE.md's own warning about this doc category. |
| ARR36-C | **Not covered by the above doc** | Consumes `distinct_object_param_pairs` — not traced this pass; the buffer-size docs above are ARR30/ARR38-scoped specifically. Flag for its own look. |
| STR31-C, ARR00-C | **A (now), migration largely complete** | Three docs (`str31c-arr00-migration-scoping.md`, `str31c-global-buffer-size-scoping.md`, `str31c-relay-function-scoping.md`) show a phased AST migration where Phases 2/3/4-partial already landed under separate task numbers, despite the first doc's own "migration NOT started" header — the later two docs cross-confirm the phases executed. One residual, explicitly-flagged limitation remains (a one-alias-hop cap on relay-function detection), left unfixed on purpose. |

### 4.4 Null-check / dereference family

| Rule | Bucket | Rationale |
|---|---|---|
| API00-C | **A** | `checks_null_params` is consumed only to *suppress* (valid-validation-pattern direction), with an explicit doc comment on the safe-direction choice ("unknown callee credits nothing," `api00_c.rs:930-934`) — the same deliberate-reasoning shape as WIN05-C. Its own positive-assertion use of `dereferences_params` (`parameter_is_dereferenced`, `api00_c.rs:1241-1274`) shares the field EXP33-C's `has_genuine_arrow_read` fix (task 1444) already hardened, so API00-C got that fix for free — **evidence that population-layer fixes propagate across every consuming rule without per-rule work**, which is itself useful signal for how to prioritize future fixes in this family. |

### 4.5 Other single-rule facts

| Rule | Field | Bucket | Rationale |
|---|---|---|---|
| ERR33-C | `never_returns` | **B, lower priority** | `check_never_returns` (`function_summary.rs:1542`) is a bare text scan (`body_text.contains("abort(")` etc.), same misfire shape as the taint family, but consumption (`is_safe_wrapper_function`) is suppression-direction only — worst case is a missed "handles errors internally" credit, not an asserted violation. Same fix class as the taint follow-up; bundle rather than separately schedule given the lower-severity direction. |

## 5. Tier 1 rules already covered by an existing, separate design doc — not re-derived here

Concurrency (CON03-C, CON07-C, CON33-C) and the ~18 macro-expansion-engine
consumers (MEM30-C, MEM31-C, EXP33-C, DCL31-C, and others — `grep -rl
macro_expand:: src/rules/` for the live list, per this file's own standing
warning against quoting a rule list in prose) both have dedicated docs:

- `docs/design/con03-con07-isr-thread-reachability.md` +
  `docs/design/concurrency-rule-evaluation.md`: **B**, a zero-reachability-
  gating gap (measured 26.3% vs. 1.8% precision with/without concurrency
  context), fully scoped against existing primitives
  (`ambiguous_call_targets`, `macro_expand`, ISR detection), header says "not
  yet implemented" as of 2026-08-27 — unconfirmed against the live task DB
  this pass, worth checking before assuming it's still open.
- `docs/design/macro-expansion.md`: **A** for the wired-in rules, engine is
  live (not merely scoped). A companion `docs/design/macro-expansion-v2-audit.md`
  exists and was not read this pass — check it before treating this family
  as fully closed.

## 6. Tier 2: the ~289 rules with no cross-file `FunctionSummary` dependency

Presumptively **(A)** *for this specific architectural question* — a rule
that never reads `context.function_summaries` cannot have EXP33-C's specific
failure mode (an interprocedural fact computed wrong and trusted blindly by
every caller). This is **not** a claim these rules are bug-free generally;
that's ADR-0005's standing policy (any misfire is a bug regardless of
corpus), a different and already-covered question, and this sweep did not
manually read any of these 289 rule bodies.

If a broader sweep of Tier 2 is wanted later, the same mechanical-first-pass
method applies: grep for raw `.contains(`/text-substring heuristics without
a corresponding AST-resolution call (the exact shape of every confirmed bug
this pass found: `cast_then_deref`, `has_genuine_arrow_read`,
`has_env03_taint_source`, `check_never_returns`) as a cheap triage signal
before reading anything closely.

## 7. Recommended follow-up tasks

None of these are filed or implemented as part of this doc — each becomes
its own scoped task, per Brandon's ruling, when picked up. Suggested
priority order and reasoning:

1. **EXP34-C / `null_state.rs::apply_cross_file_output_params_null`** —
   highest priority: a **false negative** in shared `NullState` dataflow
   infrastructure, silently marking a possibly-null pointer safe across
   every rule downstream of a conditionally-writing callee, not just
   EXP34-C. Known fix (swap to `unconditional_modifies_params`), same shape
   as EXP33-C piece (a).
2. **MEM01-C** — cheap, known fix: port EXP33-C pieces (a)+(b)'s two filters
   into `build_read_only_params`.
3. **Taint family** (ENV03-C, ENV33-C, INT30-C, INT31-C, INT32-C, STR02-C,
   INT34-C, FIO30-C) — comment/string-literal-stripping fix for
   `has_env03_taint_source`, the same fix class already proven twice this
   session; likely a meaningful real-world FP cut given the field's
   MUST-style consumption.
4. **ERR33-C's `check_never_returns`** — same fix class as #3, lower
   urgency given its suppression-only consumption direction; bundle with #3
   if convenient.
5. **MEM30-C** — trace its own consumption of `conditional_modifies_params`/
   `frees_params_guessed`/`unconditional_frees_params` specifically; do not
   assume MEM31-C's maturity transfers on field-sharing alone (MEM01-C is
   the counterexample: it shared a field with EXP33-C and did not inherit
   the consumption-side fix).
6. **ARR36-C** — not covered by the ARR30/ARR38 buffer-size docs; needs its
   own look at `distinct_object_param_pairs` consumption.
7. **Concurrency reachability gating** (CON03-C/CON07-C/CON33-C) — already
   fully scoped by existing docs; verify against the live task DB whether
   it's already in flight before filing as new, then implement per the
   existing design.
8. **Tier 2 broader sweep** (optional, lowest priority) — apply the
   text-heuristic-without-AST-resolution mechanical filter from §6 across
   the remaining ~289 rules as a cheap first pass, if the coordinator wants
   the sweep extended that far.

## 8. What this sweep did not do

- Did not manually read all 311 rule bodies — Tier 2's ~289 rules got only
  the mechanical "does it touch `function_summaries`" filter, not individual
  code review.
- Did not verify whether the existing "scoped, not implemented" docs
  (concurrency, the ARR30/ARR38 migration's remaining item) are still
  accurate against the live task DB — flagged as stale-risk per CLAUDE.md's
  own warning about this doc category's Status headers, not resolved here.
- Did not read `docs/design/macro-expansion-v2-audit.md`, which may already
  supersede part of §5's macro-expansion-family disposition.
- Did not implement, fix, or file any of §7's follow-up tasks — per
  Brandon's ruling, each becomes its own scoped task with its own
  justification when picked up, not a batch produced by this sweep itself.
