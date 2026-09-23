# EXP33-C `check_cross_file_uninit_calls`: What a Correct Check Needs

**Status:** IMPLEMENTED. (a) landed as task 1437 (`50fb0681`), (b) as task
1442 (`9ed4c319`), (d) as task 1444 (`1e180eb0`) — its mbedtls half; its lua
half turned out to be a distinct InitState gap (checked-return-value
correlation with a conditional write, not a naming convention) and was split
into task 1450 (`c9da0945`). (c) was declined as recommended below. See §6
for the outcome and what it implies for the rest of task 1434's sweep — this
doc is that sweep's first worked example, referenced rather than repeated by
`docs/design/rule-architecture-sweep.md`.

## 1. The question

Brandon's ruling on task 1418 (EXP34-C) relocated a caller-side null-argument
check to the callee's own unguarded dereference, on the principle that C has
no contract semantics: a caller handing a possibly-bad value to a callee never
itself violates a rule, only the callee's unguarded use does. Task 1419 asked
whether `check_cross_file_uninit_calls` (`exp33_c.rs:710`) — EXP33-C's
cross-file counterpart, which flags `&uninit_var` passed to a project function
classified as "read-only" on that parameter — should get the same treatment.

Measured (r720, 2026-09-21): 277 findings across 11 real-world corpora, 0 TP /
59 FP against the labeled oracle keys. A closer sample (this task) found the
FP pattern holds well past the labeled subset, via at least three distinct
mechanisms, only one of which the "relocate the check" framing from 1418
actually addresses. Brandon's ruling: dropping a CERT-C rule is not a call one
node's sample settles, and the check needs a design proposal, not an
incremental patch. This doc is that proposal.

## 2. What the check does today

```rust
if let Some(read_only_params) = read_only_fns.get(&func_name) {
    // arg is &var, var is uninitialized per InitState, and var's param
    // index is in read_only_params -> flag it
}
```

`read_only_fns` comes from `build_read_only_deref_fns` (`exp33_c.rs:59`):

```rust
let read_only: HashSet<usize> = summary
    .dereferences_params
    .difference(&summary.modifies_params)
    .copied()
    .collect();
```

Two flat, whole-program, MAY-based `FunctionSummary` sets, computed once from
a structural AST walk of each callee's body, with no CFG, no path-sensitivity,
and — critically — **no cross-file write-propagation**. `dereferences_params`
and `modifies_params` are each populated by "did this callee's own body,
scanned as text/AST, dereference/write through this parameter", full stop.

This is architecturally the same shape EXP34-C's caller-side check had before
1418 — a coarse, syntactic proxy standing in for real per-callee analysis —
but relocating the *report site* doesn't fix it, because the false positives
here aren't about *where* the check fires. They're about the callee-side
"read-only" classification itself being wrong on grounds unrelated to caller
vs. callee attribution.

## 3. Three distinct FP mechanisms found, not one

### A. Misfire in the deref side (FIXED, commit `5cf16d3a`)

`dereferences_params`'s old cast-then-deref text heuristic flagged
`*(type *)param` matches that were actually casts used as plain call
arguments (`curlx_inet_pton`'s `(char *)dst` pattern), not real
dereferences. Fixed as a narrow, self-contained bug — no architecture change
needed, and this alone cut curl's contribution to the finding count by ~14%
(84 → ~69 local findings). Unrelated to the relocation question; mentioned
here only because it's the one bucket that turned out to be a pure bug, not
an architecture gap.

### B. Indirection through function-pointer/driver-ops dispatch (the real gap)

hostap's `accounting_sta_update_stats` (`src/ap/accounting.c`) forwards its
`data` struct to `hostapd_drv_read_sta_data`, which dispatches through
`hapd->driver->read_sta_data(...)` — a function-pointer field bound at
runtime from one of several driver backends. The concrete callee is never
resolved: aurora-lint's call graph marks this kind of dispatch
`ambiguous_call_targets` rather than picking a variant (correctly, for other
consumers — see `prescan.rs`'s comment on why an ambiguous edge is treated as
*unknown*, not *absent*, for taint/free reachability). But
`dereferences_params`/`modifies_params` never learn about the write that
happens on the other side of that dispatch at all: the structural walk simply
doesn't see past the function-pointer call, so the parameter looks
untouched — "read-only" by omission, not by proof.

This is not what `check_cross_file_uninit_calls` can fix by moving where it
reports. It's the callee-side summary itself asserting a negative
("never written") that it has no way to have actually proven.

### C. A separate InitState tracking bug (filed as its own task, not part of this proposal)

hostap's `fst_session.c`: `global_sessions_list` is a file-scope static
explicitly initialized via `dl_list_init(&global_sessions_list)` before any
use, and `get_var_info_at_with_config` still reports it unsafe/uninitialized
at a later cross-file call site. This is a genuine misfire (ADR-0005: the
construct — an actual initializing write — is present and the tool asserts
otherwise) in the InitState CFG walk itself, independent of the
read-only-parameter classification or the caller/callee question entirely.
It would misfire under any architecture this doc proposes. Filed separately;
not scoped here.

## 4. What "correct" would need, broken into independent increments

### (a) Cheap, buildable now: use the MUST-write sets, not the MAY set

`FunctionSummary` already has exactly the machinery this check needs and
isn't using: `unconditional_modifies_params` / `conditional_modifies_params`
/ `modifies_params_pending`, built for EXP33-C's own direct-argument check
and carried cross-file by
`propagate_transitive_modifies` to a fixpoint. That infrastructure answers
"is there a returning path that writes nothing through this parameter" —
the actual question a MUST-uninitialized check needs — instead of
`build_read_only_deref_fns`'s current "did a flat text scan ever see a
write anywhere."

Swapping the read-only test from `dereferences_params.difference(&modifies_params)`
to something keyed off `conditional_modifies_params`/pending-obligation state
would immediately close every FP in the shape of task 1011's
`fts5CsrPoslist` pattern (a callee that writes on some but not all paths,
forwarded through another function) without inventing anything new. It does
**not** close bucket B — indirection is invisible to this machinery too,
for the same reason it's invisible to `dereferences_params` today.

### (b) Medium effort, no new whole-program analysis: an honest third state

Bucket B needs the classification to stop being binary. Add a third
disposition — *unknown-due-to-indirection* — for any callee whose body
forwards the tracked parameter into a call this tool's graph already marks
ambiguous (a function-pointer/struct-of-ops call), or into any other
callee whose own summary doesn't resolve. `check_cross_file_uninit_calls`
would then only fire on *ProvenReadOnly*, never on *Unknown* — the same
"absence of proof is not proof of absence" discipline the call graph
already uses for taint/free reachability (`prescan.rs`'s own rationale for
why an ambiguous edge is treated as an unresolved caller, not a missing
one). This needs no points-to/alias analysis: it only needs "does this
function's body hand the parameter to an unresolved call", a structural
question the codebase already asks in a different form
(`modifies_params_pending`'s forwarding detection).

Per ADR-0001 ("must be tool-provable"), collapsing *Unknown* into
*suppressed* rather than *flagged* is the correct default — an unresolved
static question should not be asserted as a violation.

### (c) Out of scope: resolving concrete indirect targets

Actually determining which concrete function a driver-ops slot points to at
a given call site is real interprocedural points-to/alias analysis for
function pointers bound at struct-init time. This project has already
declined that investment once, for a related reason and with the same
"no measured real-world driver" test
(`docs/design/cfg-substrate-adoption-decision.md` §3, and the
`ceiling-decision-alias-vs-realworld` precedent it names). Recommend the
same call here: (b)'s conservative "don't assert what wasn't proven" gets
almost all of the FP reduction (b) targets, at a fraction of the cost, and
without opening a whole-program alias-analysis investment the project has
already ruled out absent a driver stronger than one rule's FP count.

### (d) Separate, smaller: init-function/out-param conventions

A chunk of what looks like bucket B is actually a naming/contract
convention this tool has no notion of: `foo_init(&uninit_thing)`-shaped
APIs where passing something uninitialized is the entire point, and the
callee's job is to fill it in. Misfire C (§3) is one manifestation of this
at the InitState-tracking layer, but there's a separate, policy-level
question of whether the read-only/write classification should special-case
functions whose own documented contract is "this parameter is an out
parameter I initialize" — closer in shape to the existing
`documented_nonnull_params` doc-comment convention scan than to a
body-write heuristic. Worth scoping as its own follow-up once (a)/(b) land
and the residual FP shape at that point is re-measured; folding it in now
would confound the measurement of (a)/(b)'s actual effect.

## 5. Recommendation

Not a drop. Disposition for task 1434's sweep:

- **(a)** is *fixable with known infra* — reuse already-built MUST-write
  propagation, no new capability.
- **(b)** is *architecturally limited but fixable with a bounded new
  capability* — a three-state classification keyed off the call graph's
  existing ambiguity marking, not a full rearchitecture and not a new
  whole-program analysis.
- **(c)** (concrete indirect-target resolution) is *not pursued* — declined
  under the same "no measured driver" test the project has already applied
  once to a comparably-scoped alias-analysis investment.
- **(d)** (out-param conventions) is a *separate, smaller follow-up*,
  sequenced after (a)/(b) so its measurement isn't confounded with theirs.

Suggested sequencing: implement and delta-adjudicate (a) alone first (cheap,
isolated, immediately measurable), then (b), then re-measure before deciding
whether (d) is still worth scoping given the FP shape that remains. Each
becomes its own scoped task per Brandon's ruling, not implemented as part of
this proposal.

## 6. Outcome (task 1434 sweep note)

Each piece landed as its own task, in the sequence recommended above, each
verified by revert-confirmation (stash the fix, rebuild, confirm the fixture
WOULD have been flagged; restore) and a local finding-count A/B against this
checkout's own `data/benchmarks.db` (never cited as an official measurement
— see CLAUDE.md's benchmark-workflow section; official A/B +
delta-adjudication is still owed to a VLAN30-capable node):

| Piece | Task | Commit | Local EXP33-C delta |
|---|---|---|---|
| (a) MUST-write propagation, not the MAY set | 1437 | `50fb0681` | 1489 → 1473 (-16) |
| (b) honest three-state (indirect-call) classification | 1442 | `9ed4c319` | 1473 → 1468 (-5) |
| (d) out-param/init-function convention gaps (mbedtls `_init` family) | 1444 | `1e180eb0` | 1468 → 1446 (-22) |
| (d)'s lua half, split off as its own InitState gap | 1450 | `c9da0945` | -2 (lua only, direct real-world confirmation) |
| **Total** | | | **1489 → 1444 (-45, -3.0%)** |

(c) was declined as recommended, no rearchitecture attempted.

Two things worth carrying into the rest of the sweep:

- **§3's three-mechanism split held up.** What looked at first like one
  "cross-file read-only classification is wrong" problem was actually three
  independent bugs/gaps with three independent fixes and three independent
  measured deltas. A rule family flagged for the sweep's bucket (C)
  ("needs rearchitecture") is worth this same decomposition before
  committing to a rearchitecture — (b) looked like it might need real
  points-to analysis until the actual FP mechanism (indirection reaching an
  *already-marked-ambiguous* call, not an *unresolved* one) turned out to be
  answerable with a bounded new fact instead.
- **A design doc's own hypothesis needs re-verification against the real
  callee, every time**, even when the hypothesis is this doc's own. (b)'s
  proposal assumed `writes_on_all_paths`/`modifies_params_pending` might
  already catch indirect dispatch; tracing hostap's actual
  `hostapd_drv_read_sta_data` showed the coverage-proof walk requires a
  matched `if`/`else`, so a bare `if (cond) return err;` guard (hostap's
  actual shape) never even raised the obligation — a different, independent
  fact (`forwards_to_indirect_call`) was needed. Task 1450 repeated the
  pattern: filed from tracing lua's *real* `lua_getstack`/`lua_getlocal`
  pair, not from the naming-convention framing task 1444 was given.
