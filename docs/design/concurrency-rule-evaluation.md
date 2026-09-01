# Evaluation methodology for the concurrency rules (CON03-C / CON07-C / CON33-C)

**Status:** PLAN ONLY (2026-08-27, task 151). No rule code, harness code, or
TOML changed. Deliverable is this document; implementation of anything
proposed below (ISR/thread reachability analysis, a context-tagging
pre-filter, doc updates) is explicit follow-on work, filed separately.

**Driver:** Task 151 originally framed CON33-C's 3% and CON07-C's 8% Juliet
TP rates as grounds to demote/disable both rules. That framing was scrapped
2026-06-21 (Medium severity is CERT's own risk-assessment rating, not ours
to override, and the rules stay enabled). The re-scoped question: are these
numbers evidence of *bad rules*, or evidence that Juliet's CWE-matched TP
rate is the wrong instrument for scoring concurrency rules at all — before
sinking FP-reduction effort in either direction.

---

## 1. What already exists — CON03/07/33-C have real adjudicated data

This task's discovery questions turn out to already be substantially
answered by delta-adjudication work done for other reasons (task 532's
mid-tier/long-tail bundles, tasks 546/547/549). Re-litigating that data
was most of this task's actual work; nothing below required a new
benchmark run.

### Per-rule current state

| Rule | Juliet CWE(s) | Juliet TP rate | Real-world adjudicated precision (recall) | Real-world sample |
|------|--------------|----------------|--------------------------------------------|--------------------|
| CON03-C | **none** — no `cwe` key in `CON03-C.toml` | N/A (never runs in fast-mode Juliet; see §2) | 4.1% (100%) | 18 in-scope / 6 TP / 12 FP (task 547) |
| CON07-C | CWE-366, 413, 567, 667 | 8.2% (CWE-366; 13.9% flaw-detection) | 2.4% (100%) | 45 in-scope / 0 TP / 45 FP (task 546) |
| CON33-C | CWE-330, 377, 676 | 3.0% (CWE-377; 1.4% flaw-detection) | 0% (n/a — 0 TP) | 16 in-scope combined w/ CON34-C+CON37-C / 0 TP / 16 FP (task 549) |

Sources: `JULIET_COVERAGE.md` (generated from `data/benchmarks.db`),
`data/precision_audit/DELTA_BATCHC_TASK546.md`,
`DELTA_BATCHD_TASK547.md`, `DELTA_LT2_TASK549.md`.

### Root causes, already characterized per-finding

- **CON03-C** (task 547, mosquitto): 6 genuine TP — a real cross-thread
  init-guard race (`net_mosq.c:87`) and 5 signal-handler-flag visibility
  bugs (plain `bool` set in a signal handler, should be
  `volatile sig_atomic_t`). 12 FP — mosquitto's broker event loop is
  single-threaded (`no pthread_create anywhere in src/*.c`) but flagged
  anyway.
- **CON07-C** (task 546, 45/45 FP across sqlite/curl/lua/mosquitto/raylib):
  three causes — (a) flagged variable is `static const`, never mutated,
  misidentified as a compound-RMW target; (b) call site is genuinely
  single-threaded by design; (c) the signal-handler-flag idiom (set in a
  handler, polled once per main-loop tick) is a standard, correct pattern,
  not an unsynchronized RMW race.
- **CON33-C** (task 549, 0/16 combined with CON34-C/CON37-C in mosquitto):
  same single-threaded-broker misidentification as CON07-C — the checker
  fires on a fixed list of non-reentrant library function names
  (`strtok`, `asctime`, `rand`, …) with **no check at all** for whether the
  call site is ever reached from more than one thread.
- **Catapult RC624 firmware** (embedded MCU, cited in this task's original
  body): ~130/176 (76%) CON03-C findings and ~52/65 (80%) CON07-C findings
  trace to the *same* root cause in a different guise — the checker flags
  every file-scope static in any translation unit that contains a function
  named `IRQ`/`interrupt`/`ISR`, without checking whether that ISR can
  actually reach the flagged variable. A poller function named
  `DEV_APPROX_IRQProcess` demonstrates name-matching alone isn't even a
  reliable proxy for "is this really an ISR."

**These four data points — three real-world projects plus one embedded
firmware audit, four independent codebases — converge on one mechanism.**
Confirmed directly in the rule source
(`src/rules/cert_c/CONC/CON03-C/con03_c.rs`,
`.../CON07-C/con07_c.rs`, `.../CON33-C/con33_c.rs`): all three rules check
only for *nearby syntactic protection* (a `volatile`/`atomic` qualifier, a
mutex type, a lock/unlock call, or membership in a fixed unsafe-function
name list). **None of the three ever asks whether the flagged code is
reachable from more than one thread, ISR, or signal handler in the first
place.** `docs/design/internal-capability-catalog.md` confirms there is no
existing shared primitive for that reachability question — this is a real
gap, not a rediscovery of something already built.

This directly answers discovery question 2 from the task body ("is the FP
signal concentrated, or random noise") — **it is concentrated**, and it was
already concentrated and named before this task started; task 151's own
job was to notice that the existing adjudication data had already answered
it.

---

## 2. Why the Juliet TP rate is a weak instrument for these three rules specifically

Independent of the FP root cause above, the Juliet-side numbers have a
structural problem that has nothing to do with rule quality:

1. **CON03-C is invisible to fast-mode Juliet entirely.** `bench/runner.py`
   (`_resolve_manifest`) skips any CWE directory with no
   `rules_templates/cwe/CWE-<n>.toml` manifest in fast mode, and that
   manifest is generated from each rule's `cwe = [...]` TOML key
   (`data/rule_cwe_map.json`). CON03-C's TOML has no `cwe` key at all —
   it does not appear anywhere in `rule_cwe_map.json`. Fast mode (the
   default per CLAUDE.md) **never runs CON03-C against Juliet at all.**
   Full mode would run it (every rule against every CWE dir), but since
   CON03-C is never the "matched" rule for any CWE folder, its findings
   there would only ever land in `noise_count`, never in
   `cwe_matched_tp`/`cwe_matched_fp` — so even a full run produces no
   scoreable Juliet signal for this rule. The "3%/8%" framing in the
   original task body only ever applied to CON33-C/CON07-C; CON03-C had
   no Juliet number to begin with, and that absence is itself a finding.

2. **`tp_rate_pct` scores by Juliet's own bad/good line labels, not by
   whether the finding is actually a race.** `bench/analyzer.py`
   (`_classify_and_record_violation`) marks a violation TP iff its line
   falls inside Juliet's `bad_lines` for that specific CWE's flaw pattern,
   FP iff it falls in `good_lines` — regardless of which rule fired or
   whether that rule's actual concern (thread visibility, atomicity,
   reentrancy) has anything to do with the CWE-377/CWE-366 flaw the file
   was generated to demonstrate. For CON33-C in particular this is a
   double mismatch: the rule is a pure lexical name-match against a fixed
   unsafe-function list with zero thread-context gating (see §1), so it
   fires identically in Juliet's "bad" and "good" variants whenever the
   shared boilerplate happens to call one of those functions — the low
   TP rate is consistent with *the exact same context-blindness bug*
   already isolated in real-world code, not a separate Juliet-specific
   failure mode.

3. **Resolved 2026-09-01 (task 606):** whether Juliet's CWE-362/364/366/367
   templates actually construct a genuine multi-thread/signal/ISR
   execution context, or merely demonstrate the API-misuse *pattern* in a
   single execution path. Answer is **mixed, not uniform** — direct
   inspection of the corpus at `~/toolchain/benchmarks/juliet-test-suite-c`
   (present on the dev-149 node; earlier assumed absent from every non-home
   node, corrected here):
   - **CWE-362** has no test-case directory in this corpus at all — not a
     testable CWE for Juliet purposes, full stop.
   - **CWE-364** (Signal Handler Race Condition, 18 files, all one "basic"
     flow-variant family): every file registers a *real* `signal()`
     handler pointing at a real handler function. But **none of the 18
     ever call `raise()`** — the handler is installed but never actually
     delivered/invoked during the test run. The "flaw" is a pure
     ordering/non-atomicity pattern (free-then-NULL bracketing a
     `signal()` call) demonstrated on a single execution path, not an
     exercised race. (Not currently CWE-mapped to CON03/07/33-C anyway —
     see the table in §1.)
   - **CWE-366** (Race Condition Within Thread, 36 files) is the **one
     genuine exception**: every `_bad`/`good1` pair spawns two real OS
     threads via `stdThreadCreate()`
     (`testcasesupport/std_thread.c` — a thin, real wrapper around
     `pthread_create`/`_beginthreadex`), both actually run concurrently
     against the shared `gBadInt`/`gGoodInt`, and are joined before the
     function returns. This is a genuinely constructed, genuinely
     exercised concurrent execution context, not just a pattern. This is
     CON07-C's mapped CWE (§1 table).
   - **CWE-367** (TOC/TOU, 36 files) and **CWE-377** (Insecure Temporary
     File, 144 files, CON33-C's mapped CWE) are both **purely
     single-execution-path** in every file and every flow variant
     checked: no thread creation, no `signal`/`sigaction`, no `fork`
     anywhere. `access()`/`stat()` then `open()`/`write()` (CWE-367), or
     a predictable-filename call (CWE-377), all run sequentially with no
     second actor. The real-world exploit for both requires an external
     attacker process racing the check/use or filename-prediction window
     — Juliet never constructs or models that actor.

   **Consequence for "is a Juliet-based score salvageable for
   CON03/07/33-C at all":** still no, but for CWE-specific rather than
   corpus-wide reasons. CON03-C stays moot (no CWE mapping at all, §2.1).
   CON33-C's mapping is to CWE-377, which never constructs a real race in
   any variant — no version of CON33-C, however context-aware, could be
   validated against this corpus, because the corpus itself never creates
   the concurrent actor the rule is supposed to detect. CON07-C's mapping
   to CWE-366 is the one case where the underlying execution is real, but
   the thread-creation call is indirected through a wrapper function name
   (`stdThreadCreate`) rather than a literal `pthread_create`/
   `CreateThread` call in the testcase file itself — a literal-name-list
   reachability check (the shape task 608 would implement) would need to
   resolve that wrapper (in a separate TU, `testcasesupport/std_thread.c`)
   back to a real thread-creation primitive to get credit here. Confirmed
   CON07-C's current implementation does no such check at all (`grep` for
   `pthread_create`/`thread_creat` in `con07_c.rs` returns nothing),
   consistent with §1's "no reachability primitive" finding. Net: even
   the one salvageable case requires cross-TU call resolution that
   doesn't exist yet — not a quick win, and not worth pursuing ahead of
   task 608 if that ever gets scoped.

---

## 3. Answering the task's three discovery questions

**Q1 — Is there a concurrency-appropriate ground-truth corpus, vs. the
current intra-procedural scoring possibly not crediting valid hits?**
Yes, in practical terms: the real-world `ground_truth` rows from tasks
546/547/549 (61 adjudicated CON03/07/33/-adjacent findings across 4
codebases, with per-finding causal attribution already written up) are a
*better* oracle for these specific rules than Juliet, because they were
adjudicated against real multi-threaded/signal-driven programs instead of
Juliet's synthetic, likely-single-execution-path test cases (§2.3, still
open pending direct corpus inspection). Whether a *Juliet-specific*
concurrency corpus is separately worth building is lower priority — the
real-world oracle is already scoring these rules, and the Catapult
firmware datapoint adds a fourth, structurally different codebase class
(embedded/ISR) that neither Juliet nor the current orig-7 real-world
project set represents at all.

**Q2 — Is the FP signal concentrated or random noise?** Concentrated, and
already characterized (§1): one missing capability — reachability from a
concurrent execution context (thread, ISR, signal handler) — explains the
large majority of FPs in every sampled codebase (76-100% depending on
project/rule).

**Q3 — What would a defensible precision/recall number look like, and
what harness produces it?** Not a single blended percentage from either
corpus. The defensible statement is two-part, and the harness to produce
it is `bench realworld-score` extended one dimension (proposed in §4,
not built here):
  - **Recall is not the problem.** All three rules show 100% recall
    against their labeled real-world sample — they are not missing the
    TPs that exist in ground_truth.
  - **Precision should be reported split by whether concurrency-context
    evidence is present at the call site**, not as one number. The
    existing adjudication data already implies this split (single-thread
    codebases carry the FP mass); making it a first-class harness output
    turns "3%/8%/4%" into an honest, reproducible statement instead of a
    number that conflates a fixable, well-scoped gap with a claim that
    the rules are fundamentally unsound.

---

## 4. Recommended methodology going forward (plan, not implementation)

1. **Stop citing raw Juliet CWE-366/377 TP rate as a standalone quality
   signal for CON03/07/33-C** in the paper, README, or task notes. Point
   instead to the real-world adjudicated numbers in §1, with the causal
   attribution already written up in `DELTA_BATCHC_TASK546.md` /
   `DELTA_BATCHD_TASK547.md` / `DELTA_LT2_TASK549.md`. This is a doc-only
   change (`JULIET_COVERAGE.md` generation script or its consuming docs),
   filed as a follow-on task, not done here.

2. **Treat the real-world `ground_truth` pipeline as the primary
   evaluation surface for these three rules**, consistent with the
   existing CLAUDE.md delta-adjudication protocol — this task changes
   nothing about that protocol, it just confirms these rules should be
   measured there rather than via Juliet.

3. **Follow-on task A — DONE (task 606, 2026-09-01):** directly inspected
   Juliet's CWE-362/364/366/367/377 test-case source; results folded into
   §2.3 above. Verdict: not salvageable for CON33-C (its CWE-377 mapping
   never constructs a real race in any variant) or CON03-C (no mapping at
   all); theoretically salvageable for CON07-C (its CWE-366 mapping does
   construct real concurrent threads) but only after cross-TU
   wrapper-call resolution that doesn't exist yet — not worth building
   ahead of task 608.

4. **Follow-on task B (harness change, not a rule change):** add a
   concurrency-context-evidence tag to the bench/adjudication pipeline —
   for each finding, record whether its enclosing translation unit
   contains any evidence of a concurrent execution path (a
   `pthread_create`/`thrd_create`/`CreateThread` call anywhere in the TU,
   a `signal()`/`sigaction()` registration, or a function name matching
   the existing ISR heuristic) reachable from the flagged site. This is
   deliberately **not** the full ISR/thread call-graph reachability
   analysis (that's Option B from the original task-151 body / follow-on
   task C below) — it's a cheap post-hoc classifier over already-collected
   violations that can retroactively re-score tasks 546/547/549's existing
   labeled data and quantify the context-present vs. context-absent
   precision split described in §3 Q3, before committing to the more
   expensive fix.

5. **Follow-on task C (the original "Option B", gated on B's results):**
   real ISR/thread-reachability call-graph analysis, so CON03/07-C only
   fire when the flagged variable is actually reachable from a
   registered ISR or a second thread. Only worth scoping once task B
   quantifies the expected payoff (the original task-151 body's own
   estimate — "preserves ~26 CON07-C + ~46 CON03-C genuine hits" on
   Catapult alone — suggests this is real, but should be re-confirmed
   against the broader real-world set from B before committing
   engineering time, per task 150's standing "no big infra bets until the
   backlog thins" guidance).

None of A/B/C should be started as part of closing this task — file them
separately per task 151's own instruction that implementation is
follow-on work.
