# How aurora-lint findings are adjudicated

aurora-lint is a rules conformance checker; its primary ruleset is CERT C
(ADR-0001). A violation a team accepts is a deviation, not a false positive.

The rulebook for labeling a finding, and for judging whether a rule change is
correct. Each rule cites the ADR (`docs/adr/`) that decides it: the ADR
records why, and this page states what. Where the two disagree, the ADR
wins, and this page has a bug.

## A. What the oracle is

**A1. The oracle is a CERT C oracle, independent of any tool.** Each entry,
keyed `(project, commit, file, line, rule)`, records whether the code at that
place violates that CERT C rule as written, or doesn't. It would exist
without aurora-lint. (ADR-0014)

**A2. TP, FP, FN and TN exist only for a run paired with the oracle,** always
for the rule the run reports:

| | the oracle says: violation | the oracle says: not a violation |
|---|---|---|
| the run reports it | TP | FP |
| the run doesn't | FN | TN |

The stored vocabulary is TP/FP for continuity. It means violation / not a
violation. (ADR-0014)

**A3. A verdict changes only for the code's sake:** a ruling that changes
what counts as a violation, or a better reading of the code. Never because a
run changed. A finding that goes away turns a TP into an FN (capability lost)
or an FP into a TN (the tool improved). The label stays. (ADR-0014)

**A4. Labels on lines no run reports are the regression safety net.** A
not-a-violation label there is re-examined when a run reports the line again,
not to keep up with a new ruling. A violation label there is an FN in every
run's recall, so it is re-examined whenever a ruling changes its basis.
(ADR-0014)

**A5. The oracle is incomplete by necessity.** It covers what runs have
reported plus the known misses. Recall is measured against the violations it
knows about, and every recall figure says so. (ADR-0014)

**A6. A label is not an exploitability claim.** Many violations are minor
departures from the rule as written. Labels get revised. (ADR-0007)

## B. Is the construct a violation?

**B1. Identify first, then prove.** If you can't tell what construct is on the
line (which declaration a name refers to, an operand's type, whether a token is
preprocessor text), the rule says nothing: a guess is a misfire. Once the
construct is identified, only a proof makes it safe. Not being able to prove it
safe means it is reported. (ADR-0006)

**B2. A construct is a violation unless an accepted basis proves it safe.**
Accepted, strongest first (ADR-0011):
1. **Language and standard-library guarantees.** What ISO C requires of every
   implementation, and what the ISO C and POSIX standard libraries specify for
   their functions (`argv[argc] == NULL`; static storage is zero-initialized;
   `free(NULL)` does nothing).
2. **Code dead as written.** `#if 0`, a `defined(X)` arm settled by an
   unconditional `#define`/`#undef` in the same file, `__cplusplus` when
   building C. Nothing else is dead. (ADR-0010)
3. **Proof in the scanned source.** A dominating check; an assert or abort
   macro no configuration strips; a callee that provably tolerates the value;
   every caller of a closed function provably checking it.

Not accepted:

4. **Compiler, platform or implementation behavior.** `-fwrapv`, widths on the
   benchmark host, a library's behavior beyond ISO C and POSIX, attributes like
   `nonnull` or `noreturn`.
5. **Inference.** "No caller passes NULL", "the tests cover it", "obviously
   intentional", an `NDEBUG`-strippable `assert`, a runtime switch that is off
   by default.

**B3. Every compilable configuration counts.** A violation in an arm some
build can compile is a violation, whatever flags a normal build uses. Exclusive
arms are alternatives: a finding that only exists by combining two arms that
never compile together is a misfire. (ADR-0010)

**B4. The primary configuration guides; it never proves.** It decides what an
oracle scores, and it picks among platform-specific definitions of a typedef,
enum or macro. A fact that follows only from that pick (a width, a signedness)
is not proof. Questions of reach, like "can this be called from outside" or
"are all paths to it checked", look at every compilable configuration.
(ADR-0010)

**B5. Asserts depend on the policy setting.** Label the strict verdict: a strippable
`assert` guards nothing. Tag the row as assert-dominated when a dominating
assert establishes the property, because the default policy treats that assert
as a guard. A violation inside an assert's argument is a violation under
both policies. An assert macro no configuration strips, whose failure path never
returns, is a guard in both. (ADR-0010, ADR-0015)

**B6. Policy and environment.** The oracle is the strict, freestanding truth,
plus tags for each relaxation: assert-dominated and dependent site (policy), and
library-contract trust, naming the contract (environment), and a rule-specific
relaxation, naming it (for example FLP00-C's exact-zero comparison). Each setting's
figures are computed from those. Published figures use the ISO C and POSIX
contract model. (ADR-0015)

## C. Settled cases (ADR-0011 unless noted)

- **C1. `main()`:** `argv` is never NULL. `argv[i]` without an `argc` bound is
  a violation. `argc` is judged like any integer parameter.
- **C2. Static storage is zero-initialized:** reading it is not a use of an
  indeterminate value.
- **C3. Anything that could be publicly callable is an API.** A library the
  tree builds for outside use; an executable linked with `-rdynamic` or
  `--export-dynamic`; `dlopen`ed plugins; registered callbacks; exported ops
  tables. Its caller set is open, and in-tree callers prove nothing about its
  inputs. Why the export exists doesn't matter.
- **C4. Code no real build in the tree exports stays closed.** A third-party
  shim the tree doesn't use doesn't count.
- **C5. A static function is closed only while its address stays in the
  scanned source.** Stored in an ops table, registered as a callback, passed to
  a plugin interface: it's as open as whatever reaches it.
- **C6. Every caller checks:** for a closed function with at least one call
  site, if every call site provably tests the value, the use inside is safe.
  No callers means no caller-side proof. Uncertain means it's reported.
- **C7. A proof chain must end in a real proof.** A caller's earlier
  dereference is not a check: it moves the fault up a frame. The chain counts
  only if it ends in a test, a language guarantee, or an address-of or literal
  argument.
- **C8. A callee's postcondition** (for example, non-NULL on every success
  return) counts when its body proves it on every return path and the caller
  tests the return code.
- **C9. Data invariants need every writer in the scanned source.** "This
  global never holds NULL" is proof only for static storage whose address
  doesn't escape, or a type opaque to outside code. Static functions write
  globals too.
- **C10. A `(pointer, length)` pair is a contract, and a contract is not
  proof.** It's a violation unless every call site provably passes a buffer of
  that length, which needs a closed caller set.
- **C11. Integer widths:** only the ISO minimums and the exact width of an
  exact-width type are proof.
- **C12. noreturn:** a body verified never to return, or the standard
  library's noreturn functions. Under the default policy, an ISO `_Noreturn`
  declaration too; never a compiler attribute or a macro's name. (ADR-0011,
  ADR-0015)
- **C13. A correlation inside one function** (a flag set only when a pointer
  was tested) is proof when the function's own code establishes it on every
  path, with no reassignment in between.

## D. Where a finding lives (ADR-0012)

- **D1. EXP34-C lives at the dereference.** That includes a call into a
  standard library function whose ISO C or POSIX specification requires a valid
  pointer. A plain `f(p)` into a project function is never the site. A bare
  `nonnull` attribute is only a trace note.
- **D2. `&p->field` and `&p->a[i]` with `p` unproven are dereference sites.**
- **D3. The first site of failure is the site.** Report the first unguarded
  dereference, even when a later test shows the pointer may be NULL.
- **D4. API00-C lives at the receiving function.** It is a violation when the
  function is externally reachable, a pointer parameter is used without a
  validating test on some path, and the use is a dereference, a forward to a
  callee that dereferences it unchecked or that the function can't vouch for
  (not in the scanned source, a function pointer, an ops table, a registered
  callback), or a store for later use.
- **D5. API00-C is reported separately from EXP34-C.** It's a recommendation
  with no external benchmark; headline null-dereference figures are EXP34-C's.

## E. Writing the label

- **E1. An FP names its basis concretely:** the clause of the standard, the
  guarding line, or the enumerated call sites. "Internal contract", "caller
  always passes valid" and "not attacker-controlled" name no basis.
  (ADR-0011)
- **E2. A TP's reason says what the construct is and why it violates the rule
  at that line.** "Not compiled in a normal build" is not a reason.
  (ADR-0010)
- **E3. A reason never asserts exploitability or reachability from untrusted
  input, quantifies an overflow, names a triggering input, or points at an
  unpublished reproducer or patch** until the fix has landed upstream.
  (ADR-0007)

## F. Judging a rule change

- **F1. A misfire is always a bug:** the finding names a construct a reader of
  the line can't find there. Fix it, on any corpus. (ADR-0005)
- **F2. A judgment FP is not fixed in the rule.** The construct is real and
  someone decided it doesn't matter. Suppression and per-project config handle
  it. (ADR-0001)
- **F3. Right for the wrong reason is a bug too.** A finding reached only
  through unsound evidence is removed even on a line the oracle marks a
  violation. The run then misses it (FN), and that lost recall is reported.
  (ADR-0005)
- **F4. Resolve identifiers by declaration, never by spelling.** The file's own
  definitions win over project-wide maps. (ADR-0006)
- **F5. `ERROR` ancestry is not a suppression signal.** Diagnose the misread,
  usually preprocessor text read as a C expression. (ADR-0008)
- **F6. A 0% real-world TP rate is not a reason to drop a rule.** (ADR-0002)
- **F7. Juliet section scoring is not line truth.** A Juliet hit means "fired
  in the flawed function", not "named the flaw". A misfire fix that removes
  such hits is still a fix. (ADR-0005)

## G. Which rules ship (ADR-0013)

- **G1.** A rule ships if a sound detector can ever find a true violation, and
  its findings aren't structurally FP-dominated on any codebase. Decided from
  the rule's nature, never from benchmark counts.
- **G2.** Each rule gets one disposition: deterministic; deterministic with
  review; environment-gated; unenforceable; fails the criterion.
- **G3.** Anything Juliet covers ships.
- **G4.** Every rule, including one marked for review, is labeled against its
  written scope: the construct its disposition row names and the exceptions
  written into it. Whether the author meant it is the user's call, handled by
  suppression. The oracle doesn't record it. CERT's "Detectable: No" alone
  doesn't make a rule unenforceable if a decidable checkable form exists.
- **G5.** A rule not shipped is removed from the tool, one justified change at
  a time. It's published with its reason in README.md, the docs and the paper.
