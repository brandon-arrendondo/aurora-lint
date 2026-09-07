# seL4 onboarding + MSC12-C precision measurement — sqc v0.4.222 (run sqc-0.4.222-c52f9692, run #163, 2026-08-20)

Task 381: find and onboard an 8th real-world oracle codebase specifically to
give MSC12-C (empty-body/no-effect-code detection) its first real precision
measurement on a project that actually follows a no-empty-body convention —
MSC12-C had been categorically disabled in all 7 existing oracles
(`data/precision_audit/msc12_msc13_0.4.141/README.md`) with 0% measured
precision on two independent samples there.

## Candidate: seL4 microkernel

[seL4](https://github.com/seL4/seL4) (`@1326364`, cloned 2026-08-20) is a
formally verified microkernel with a public
[C style guide](https://sel4.systems/Contribute/style.html) prohibiting
dead/no-op code; its functional-correctness proof against an Isabelle/HOL
spec is a strong structural argument against *accidental* dead code. Before
onboarding, a literal grep for `if/for/while (...) {}` across the whole
kernel (`src/`, 183 `.c` files, ~50k lines) returned **zero** hits — a much
cleaner signal than curl/mosquitto/hostap's pervasive deliberate no-op
idioms. On that basis it was onboarded as CODEBASES["sel4"]
(`mcp_servers/realworld_server.py`), scoped to `src/` (the kernel proper;
`libsel4/` is the userspace binding library, not kernel code).

## The literal-braces grep missed the real idiom

Sampling and reading 40 of the resulting 180 MSC12-C findings (seed 20260820,
`data/precision_audit/sel4/adjudication_msc12_0.4.222.csv`) found the grep's
premise was wrong: the dominant empty-body idiom in low-level C is `while
(cond);` — a bare-semicolon busy-wait polling loop, not `while (cond) {}` —
which the grep never matched. seL4's driver/platform code is full of it
(UART TX/RX-ready polling, VT-d completion-bit polling, IRQ-controller reset
polling). Combined with two more idiom families also already characterized
in the other 7 oracles — documented no-op function/case stubs
(`/* Don't need to do anything */`, platform-abstraction shims with no L2
cache to operate on) and macro-hidden real effects (`NODE_UNLOCK_IF_HELD`,
`SCHED_APPEND_CURRENT_TCB`, `IPI_MEM_BARRIER`) — these three families account
for 36 of the 40 sampled findings.

**Measured precision: 10.0% (4 TP / 40 labeled)** — `bench realworld-score
sqc-0.4.222-c52f9692`. Higher than the other 7 oracles' 0%, but for a
mundane reason: 4 genuine stray double-semicolons (`stmt;;`, a real if
harmless typo pattern — `src/arch/arm/32/model/statedata.c:43`,
`src/fastpath/fastpath.c:215/452/881`), not evidence that seL4's control-flow
bodies are meaningfully cleaner than any other systems-C codebase's.

One seL4-specific FP family not seen in the other oracles: two findings
(`src/arch/x86/64/object/objecttype.c:233,239`) are "empty" if/else branches
that actually contain Isabelle proof-annotation comments (`/** AUXUPD: ...
*/`, `/** GHOSTUPD: ... */`) consumed by seL4's verification toolchain — a
misattribution class unique to formally-verified codebases.

## Conclusion

**The premise "some real-world C codebase avoids MSC12-C's no-empty-body
false positives entirely" does not hold**, at least not among systems/kernel
C: busy-wait polling loops and no-op platform stubs are load-bearing idioms
of low-level hardware-facing C in general, seL4 included, not a code-quality
gap specific to the other 7 (mostly userspace) oracles. MSC12-C stays
disabled for seL4 too (`conf/realworld/sel4-rules.toml`), consistent with the
other 7.

What *was* accomplished: MSC12-C now has a second real measured sample (10%,
vs. 0% twice before) confirming the same root causes generalize to a
structurally very different (formally verified, freestanding kernel)
codebase, and seL4 is onboarded as a genuine 8th real-world oracle for the
suite generally (novel domain — no libc, no POSIX, hardware-facing) even
though it didn't resolve the MSC12-C-specific goal task 381 set out for.

**Recommendation**: the actual fix is in the detector, not further corpus
hunting — teach `check_empty_control_flow` to recognize the `while
(cond);`/`for (...);` busy-wait idiom (bare-semicolon body polling a
volatile/memory-mapped condition) as intentional, the same way task 379/380
taught `check_empty_switch_case` to recognize grouped case labels. Filed as
a follow-up (see todo-sqlite-cli).

## Update: fixed in v0.4.223 (commit ca163f93, task 473)

Both `check_empty_control_flow` (braced-empty `while (cond) { }`/`for`/`do`
bodies) and `check_no_effect_expression` (bare-semicolon `while (cond);`
form, including the `while (cond) { ; }` variant) now skip the empty body
when the loop's condition invokes a function, or reads through
pointer/field/array indirection *combined with* an explicit
comparison/bitwise/logical operator — the "polling with a mask/comparison"
signature that covers essentially every real busy-wait in this sample
(`*UART_REG(x) & MASK`, `timer->stat != DONE`, `vtd_read(...) & 1`).
Deliberately narrow: a bare dereference/field-read with no operator
(`while (*flag);`, `while (!timer->tistat);`) is structurally
indistinguishable from a forgotten loop body and stays flagged — this is
pinned down by the pre-existing test `tests/fail/testcases_empty_while_body.c`
(`while (*flag) { }`), which the fix must not regress.

**Real-world impact** (sqc-0.4.223-ca163f93 vs. sqc-0.4.222-c52f9692, same
seL4 checkout): MSC12-C's raw finding count on seL4 dropped **23.9%**, 180 →
137 (all 43 removed were the `while`/bare-semicolon busy-wait "Stray
semicolon"/"Empty while loop body" messages; every other MSC12-C sub-check's
count was unchanged), with zero change to any other rule (5143 → 5100 total
findings, an exact match). Full test suite: 3760 passed, 0 failed — no
regressions, including the 40-item pre-fix sample re-verified against the
post-fix run.

**Re-measured precision** on the post-fix run, adjudicating a fresh
40-finding sample plus tracking all 4 previously-confirmed TPs (all
double-semicolon typos, all still present — recall held):

| | Pre-fix (0.4.222) | Post-fix (0.4.223) |
|---|---|---|
| MSC12-C raw findings | 180 | 137 |
| Sample labels accumulated | 40 | 59 (union of both samples still present in the post-fix run) |
| TP (labeled findings) | 4 | 5 |
| Sample/oracle precision | 10.0% | **8.5%** (`bench realworld-score sqc-0.4.223-ca163f93`) |

The nominal percentage moved within sampling noise (5/59 vs. 4/40) rather
than jumping, because precision here is bottlenecked by the *other* FP
families this fix didn't touch (documented no-op stubs, deliberate empty
switch cases, macro-hidden lock/barrier statements, and — new in this
sample — two misattribution classes: seL4's Isabelle proof-annotation
comments (`/** AUXUPD/GHOSTUPD ... */`) inside "empty" if/else branches, and
an attribute-macro-decorated declaration (`BOOT_BSS rootserver_mem_t
rootserver;`) misread as a discarded-expression statement). What the fix
demonstrably did: cut the raw finding volume by a quarter with zero
recall cost, confirmed against a real, disjoint 40-item resample. The
remaining FP families are each their own smaller, separate fix — filed
as tasks 474-477.

## Update: task 477 fixed in v0.4.224 (commit 0264c3b7)

`BOOT_BSS`-decorated declarations (seL4's section-placement attribute
macro, e.g. `BOOT_BSS rootserver_mem_t rootserver;`) confused tree-sitter's
error recovery into splitting the declaration into a `declaration` node
with a synthesized `MISSING ";"` plus an orphan `expression_statement` for
the trailing identifier — `check_no_effect_expression` then flagged that
orphan identifier as a no-effect bare-identifier statement.
`check_no_effect_expression` now skips an expression_statement whose
immediately preceding sibling is a `declaration` containing a `MISSING`
node anywhere in it (same family as the pre-existing
ERROR+function_declarator skip, different malformed-declaration shape).

**Real-world impact**: seL4 MSC12-C findings 137 → 133 (4 removed: the
original `src/kernel/boot.c:24`, plus three more of the identical
`BOOT_BSS` pattern found by the fix generalizing correctly —
`src/arch/x86/kernel/boot_sys.c:52,57` and
`src/arch/x86/machine/cpu_identification.c:21`), zero additions, zero
change to any other rule (5100 → 5096 total, exact match). Full suite:
3760 passed, 0 failed.

## Update: task 474 (partial) fixed in v0.4.225 (commit 36feac10)

`check_empty_function` flagged the pervasive "documented no-op stub" idiom
(`/* Don't need to do anything */`, `/* Nothing to do */`, `/* Do nothing
*/`) as dead code — an empty function body containing at least one
comment is now treated as documented, not forgotten, and skipped.

A first attempt applied the identical exception to
`check_empty_control_flow` (if/else/for/while bodies) too, but that broke
4 of CERT's own canonical MSC12-C wiki examples
(`tests/fail/wiki_{,non}compliant_{1,2}.c`) plus 4 synthetic tests: CERT's
own textbook illustrations of an empty *branch* use the exact same "lone
placeholder comment in an otherwise-empty block" shape (`/* Handle error
*/`, `/* This code is unreachable */`) to demonstrate the violation being
detected. That part of the fix was reverted — the comment-implies-
documented heuristic only holds for whole function bodies, not
control-flow branches, and is scoped there.

**Real-world impact**: seL4 MSC12-C findings 133 → 120 (-9.8%; 13
removed, all confirmed documented-stub instances — `Arch_activateIdleThread`,
`Arch_postModifyRegisters`, `Arch_prepareNextDomain`,
`Arch_prepareSetDomain`, `handleSpuriousIRQ`, `Mode_postModifyRegisters`
across arm/riscv/x86 — see
`data/precision_audit/sel4/adjudication_msc12_task474_0.4.225.csv`), zero
additions, zero change to any other rule (5096 → 5083, exact match). Full
suite: 3761 passed, 0 failed. Combined precision across all task
381/473/474/477 labels: 10.0% (5 TP / 50 labeled),
`bench realworld-score sqc-0.4.225-36feac10`.

**Still open**: task 474's other sub-problem, a deliberate empty switch
case with a bare `break;` and no comment at all (`case
cap_asid_control_cap: break;`, `case EPState_Recv: break;`, `default:
break;`), is untouched — there's no comment signal to key off, and this
fix was deliberately kept narrow after the control-flow near-miss above.
Left open pending a different approach (see task 474's remaining notes in
todo-sqlite-cli).

## Update: task 474 closed in v0.4.226 (commit 23ae3f12) — confidence, not a heuristic

Confirmed this sub-problem is genuinely ambiguous, not a detection gap: a
real seL4 instance (`src/api/syscall.c:242`, `default: break; /* syscall
is not for benchmarking */`) DOES carry an explanatory trailing comment
justifying the no-op, structurally identical to
`check_empty_switch_case`'s own existing test fixture
(`tests/fail/testcases_empty_switch_case.c`, `/* empty case body —
VIOLATION */` before a `break;`) which demonstrates the opposite verdict
with the same shape. Comment presence cannot disambiguate this case any
more than it could for if/else/for/while bodies.

Rather than force a heuristic that can't actually be confident,
`check_empty_switch_case` now sets `requires_manual_review: Some(true)`
on its findings — the same pattern 23 other rules (CON43-C, MEM10-C,
etc.) already use for genuinely ambiguous cases. This surfaces as `low?`
instead of `low` in CLI output and remains fully suppressible per-finding
via the existing `SQC-SUPPRESS`/`suppress.toml` mechanism with a
justification — both mechanisms already existed, just weren't wired up
for this check. No change to finding count (still 120 on seL4 — this is
a confidence/severity-display change, not a detection change) or to any
other rule. Full suite: 3761 passed, 0 failed.

(Noted but out of scope here: the JSON/SARIF/CSV/Excel exporters don't
currently serialize `requires_manual_review` at all — the `?` marker is
CLI-stdout-only, a gap affecting all 24 rules that set it, not just this
one. Filed as a follow-up.)

## Update: task 478 fixed in v0.4.227 (commit c89daa9f) — export serialization

The gap noted above is closed: `requires_manual_review` now serializes in
all four export formats (`JSON`'s own boolean field, SARIF's
`properties.requiresManualReview` extension bag, and a `[NEEDS MANUAL
REVIEW]` title prefix + description note for CSV/Excel's fixed
Azure-DevOps-work-item schema), and `bench/db.py`'s `realworld_violations`
table gained a matching column so the benchmark pipeline captures the
signal too. No detection change, no finding-count change. Full suite:
3761 passed, 0 failed.

## Update: task 475 fixed in v0.4.228 (commit 9b959b7e) — macro-hidden lock/barrier statements

`check_no_effect_expression`'s bare-identifier-as-statement branch now
skips an identifier when it's a known `#define` object-like macro —
reusing DCL40-C's existing mechanism (`is_defined_macro_name` against the
current file's source, plus `ProjectContext::defined_macro_names`
collected cross-file during `-d` pre-scan and threaded in via
`set_project_context`) rather than a new name-heuristic. This mirrors the
rule's existing `call_expression` exception for macros invoked with `()`,
extended to the parenthesis-less object-like form. Confirmed real: seL4's
`NODE_LOCK_SYS`/`IPI_MEM_BARRIER`/`SCHED_APPEND_CURRENT_TCB` all have real
`#define`s in header files (`include/smp/lock.h`,
`include/arch/*/machine/hardware.h`, `include/object/tcb.h`) expanding to
a lock acquire/release, a memory-barrier instruction, and a real
scheduler-queue append respectively.

**Real-world impact**: seL4 MSC12-C findings 120 → 84 (-30%, 36 removed,
all confirmed bare-macro-identifier statements — the exact family task 475
was filed for), zero additions, zero change to any other rule (5083 →
5047 total, exact match — expected, since the fix is fully contained
inside MSC12-C's own identifier branch and can't touch any other rule's
checks). Full suite: 3762 passed, 0 failed, including the new pass
fixture `tests/pass/testcases_object_macro_statement.c`.
`bench realworld-score 168` (run `sqc-0.4.228-9b959b7e`): recall held at
5/5 (all previously-confirmed TPs still flagged); labeled-sample precision
15.6% (5/32) vs. the prior 10.0% (5/50) — not a real precision gain, just
a shrinking labeled denominator as fixed FPs drop out of the run; 52/84
(61.9%) of this run's MSC12-C findings remain unlabeled and would need
delta-adjudication before any precision claim beyond "recall held, raw
FPs of this family eliminated."

**Still open**: task 476 (seL4's AUXUPD/GHOSTUPD Isabelle proof-annotation
comments misread as empty if/else branches).

## Update: tools_sqc task 1016 — a bare-dereference busy-wait on a `volatile` object

The bare-dereference exclusion pinned down by the task 473 section above
(`while (*flag);`, `while (!timer->tistat);` stay flagged, because
structurally they are indistinguishable from a forgotten loop body) is now
lifted for one specific case, on the evidence that section asked for:
`volatile`.

A volatile read cannot be hoisted out of the loop, so a condition that reads
a volatile object re-reads it every iteration *by definition* and the empty
body is the idiom. The non-volatile form really is a bug — the compiler is
free to hoist the read and turn the loop into an infinite one. That is a
distinct semantic signal, not a widening of the dereference predicate, so
`condition_indicates_polling` gained a `volatile` disjunct rather than a
looser structural one. It needs no operator and no indirection at all:
`while (!node_boot_lock);` reads a bare identifier.

The obstacle was scope. `mentions_volatile_operand` (which
`check_subsumed_guard` already used, and which is left untouched) only scans
declarations *inside* the containing function, and seL4 declares every object
its busy-waits poll at file scope. `Msc12C` now carries a per-file set of
file-scope `volatile` names, collected once per translation unit in `scan`
via `ast_utils::file_scope_descendants_of_kinds` — deliberately not an
ancestor walk to the translation unit per candidate loop, which is the shape
that cost CON40-C 23 s on deeply nested input (task 952). The per-function
half is still consulted, from a stricter collector that reads only the
declarator, so `volatile struct l2cc_map *const l2cc = (volatile struct
l2cc_map *)L2CC_L2C310_PPTR;` contributes `l2cc` and not the non-volatile
`L2CC_L2C310_PPTR` its initializer names. It runs only after the cheap
structural checks have declined, i.e. only for a loop that was about to be
reported.

**Real-world impact** (local probe scans of this checkout against baseline
`117d1624`, runner-equivalent invocation — `src/` scan,
`conf/realworld/sel4-rules.toml`, the same `-d`/`-I` pairs
`bench/realworld_runner.py` passes): seL4 MSC12-C findings 17 → 14 (3
removed, zero added), with all-rule totals 5514 → 5511, an exact match — the
change is fully contained inside MSC12-C's polling predicate. The three:

| file:line | condition | declaration |
|---|---|---|
| `src/arch/arm/kernel/boot.c:272` | `while (!node_boot_lock);` | `BOOT_BSS static volatile _Atomic int`, file scope |
| `src/arch/riscv/kernel/boot.c:156` | `while (!node_boot_lock);` | `BOOT_BSS static volatile _Atomic word_t`, file scope |
| `src/arch/arm/machine/l2c_310.c:381` | `while (l2cc->maintenance.clean_inv_way);` | `volatile struct l2cc_map *const l2cc`, file scope |

A whole-repo `--rules MSC12-C` sweep of all nine pinned checkouts with both
binaries moved nothing outside seL4 (curl 50, hostap 151, libcrc 0, lua 2,
mosquitto 41, pureftpd 5, raylib 64, sqlite 94 — byte-identical both sides).
No measurable runtime change on seL4, sqlite or raylib. Full suite: 4093
passed, 0 failed, including the two new fixtures
`tests/pass/testcases_volatile_busy_wait.c` and
`tests/fail/testcases_nonvolatile_busy_wait.c`.

**These are probe-scan numbers from one checkout, not a project measurement**
— nothing here went through `benchmarking_db`'s queue, so none of it is
citable as a project figure, and no precision/recall claim is made. What it
does establish is the raw delta and the absence of collateral.

**Deliberately still flagged**: `src/drivers/timer/omap3430-timer.c:40,63`,
`while (!timer->tistat);`. `timer` is a plain `timer_t *` and `tistat` a
plain `uint32_t` in `include/drivers/timer/omap3430.h` — a memory-mapped
register the header never marks volatile. Under the rule above these stay,
which is the conservative answer and arguably the right one.
