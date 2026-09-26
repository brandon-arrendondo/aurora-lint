# 0012. Where a finding lives: EXP34-C at the dereference, API00-C at the entry point that hands an unvalidated pointer on

## Status

**Proposed — draft for Brandon, not accepted** (aurora_lint 1572,
2026-09-25). No rule or label changes until this is decided. The evidence,
both options argued, and the label counts are in
`docs/design/finding-location.md`. If accepted, change this line to
"Accepted (Brandon, <date>)". If (a) is chosen instead, rewrite the Decision
and keep the record.

## Context

A function receives a pointer and never dereferences it. It only forwards
it: to a callee, into an ops table, or to a registered callback. The same
shape has been labeled TP and FP in different passes:

- **The API00-C task-664 convention.** A parameter forwarded to a
  dereferencing callee is unvalidated, so the function is TP. This comes
  from the bmdb 664 pointer sample and the 769/793-796 standard.
- **The EXP34-C site rule.** aurora-lint 4bbf15d1, Brandon's 2026-09-21
  ruling: a caller passing a possibly-null pointer to a project function
  never violates EXP34-C by itself.

Each ADR-0011 re-pass (bmdb 1541, 1551, 1553, 1554) had to decide which
reading applies. The live cases:

- hostap `autoscan.c:143`, which forwards into the `notify_scan` ops
  callback, is TP.
- The `wpa_msg` family, which forwards an opaque `ctx` to registered
  callbacks, is FP.

The research (design doc) found four things:

- **CERT places API00-C's violation at a non-dereferencing function.** Its
  noncompliant `setfile` only stores its parameter. CERT also places
  EXP34-C's at a forwarding call into a library callee (`strlen`, `memcpy`).
- **Dereference-based tools** (Coverity, Klocwork, Infer, Clang, GCC,
  cppcheck, Frama-C, Polyspace) never report a bare forwarder. They anchor
  at the null evidence or at the dereference, and forwarding frames become
  trace notes.
- **Juliet and NIST Ockham place CWE-476 at the dereference,** or at a
  library call. Juliet has no CWE-20 ground truth, and Ockham calls the site
  of a missing check "still open".
- **The one API00-C tool precedent** for a non-dereferencing site is
  Polyspace's CERT API00-C checker, which flags an unchecked store of a
  parameter.

Under a strict dereference-only reading, about 860 current API00-C TP labels
(about 13%) would flip to FP. Most are hostap.

## Decision

The two rules keep their different sites, because they ask different
questions.

1. **EXP34-C lives at the dereference.** That includes a call into a
   standard library function whose ISO C or POSIX specification requires a
   valid pointer (`strlen`, `memcpy` with nonzero `n`, and so on). A bare
   `nonnull` attribute is a compiler annotation, not a standard contract
   (ADR-0011 basis 4), so it appears only as a trace note, never as the
   site. It includes `&p->f` with `p` unproven, by the strict
   reading. A plain `f(p)` into a project function is never an EXP34-C site
   (4bbf15d1, unchanged).
2. **API00-C lives at the receiving function.** It is TP when all three
   hold:
   - the function is externally reachable, meaning its caller set is open
     under ADR-0011 (non-static in a library or an exported executable);
   - a flagged pointer parameter is used without a validating test on some
     path;
   - that use is one of:
     - a dereference;
     - passing it to a callee that dereferences it unchecked;
     - passing it to a callee the function cannot vouch for: a body not in
       the scanned source, a function pointer, an ops-table slot, or a
       registered callback;
     - storing it for later use.
3. **API00-C is FP** when any of these holds:
   - the function tests the parameter;
   - every use is null-tolerant as written;
   - the caller set is closed and every caller proves the value (ADR-0011).
4. **Report API00-C separately from EXP34-C,** with this site convention
   stated. It is a CERT L3 recommendation with no external benchmark ground
   truth. Headline null-dereference figures are EXP34-C's.

5. **The first site of failure is the site.** When a pointer is
   dereferenced unguarded (`p->x`) and a later test (`if (p && ...)`) shows
   it may be NULL, the violation is the first dereference. Report it there;
   don't silently drop both the dereference and the later disjunct. Later
   sites that depend on the first may not show until it is fixed (ADR-0011,
   proof chains).
6. **`&p->field` and `&p->a[i]` with `p` unproven are dereference sites.**
   They evaluate member access through `p`, which is undefined for a null
   `p` (C11 6.5.2.3; 6.5.3.2 exempts only `&*E` and `&E[i]`). A plain `f(p)`
   still isn't a site (item 1).

## Consequences

- **No existing API00-C TP flips for resting on forwarding alone.** The
  task-664 convention is the policy, now written down.
- **Opaque-context callbacks become TP (the `wpa_msg` family).** Item 2 makes
  a registered callback a callee the function cannot vouch for. Treating a
  documented-optional `void *` as "nothing to validate" would rest on the
  documented contract, which is ADR-0011 basis 5. If Brandon rules the other
  way, write the exception here, naming the construct.
- **A rule change can teach API00-C** to follow a forwarded parameter into an
  in-tree callee's body and find a null-tolerant sink. That is recognizing
  proof in source (ADR-0011 basis 3), not a suppression heuristic. It cannot
  stop reporting a forward into an opaque callee.
- **EXP34-C precision and recall stay comparable** with other tools and with
  Juliet, because its sites are theirs. API00-C figures are not comparable
  to any tool's and must not be presented as if they were.
- **One defect in a leaf helper can make several exported wrappers API00-C
  TPs.** That is intended under this decision (each entry point fails to
  validate), and it is why API00-C is not folded into the headline
  null-dereference count.
- **This does not revisit** ADR-0011's proof bases, the libc exception, or
  the strict address-of reading.
