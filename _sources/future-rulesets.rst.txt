==============================
Future Rulesets Beyond CERT C
==============================

This page documents embedded coding standards and rule families that predate or
complement MISRA and could be added to SqC in the future. All listed rules are
freely implementable — they come from open/public-domain standards.

Why CERT C Is The Base Standard
================================

Everything below is framed as complementing MISRA, which only makes sense once
you know why MISRA is not what SqC implements. It is a fit-to-domain choice,
not a fallback:

- **CERT C is open.** Public and freely implementable, so every rule SqC
  enforces can be read and checked against the analyzer's behaviour. That is
  load-bearing for this repo specifically: the false-positive work is
  reviewable because a reader can look up what the rule actually says, and the
  ground-truth oracle's TP/FP verdicts are arguable against a published text
  rather than a licensed one.
- **The overlap with MISRA is strong.** The two address the same defect
  classes for the most part. CERT C reaches further into security — untrusted
  input, integer conversion, resource lifetime — while MISRA reaches further
  into language-subsetting discipline.
- **The residual difference is process, not coverage.** MISRA's
  mandatory/required/advisory apparatus, its subsetting rules and its
  certification-oriented deviation process exist to satisfy a certification
  body. SqC does not implement that apparatus. That is a statement about what
  SqC is and not about who should use it — nothing here is domain-restricted,
  and C written for automotive, medical or aerospace is subject to these rules
  like anyone else's.

So the question this page answers is not "what would we add if we could afford
MISRA" but "which open standards add coverage CERT C does not already give
us". Two rules on that list are already implemented — see the note under
The Power of 10 Rules below.

The Power of 10 Rules (NASA JPL, 2006)
=======================================

Created by Gerard J. Holzmann at NASA's Jet Propulsion Laboratory, these 10
rules eliminate C coding practices that make code difficult to review or
statically analyse. They complement MISRA C guidelines.

1. **Restrict control flow** — avoid complex flow constructs like ``goto`` and recursion.
2. **Fixed loop bounds** — all loops must have fixed upper bounds (prevents runaway code).
3. **No dynamic memory after init** — do not use dynamic memory allocation after initialisation.
4. **Function size limits** — no function longer than ~60 lines (one printed page).
5. **Assertion density** — average at least two assertions per function.
6. **Limited scope** — declare all data objects at the smallest possible scope.
7. **Check return values** — check the return value of all non-void functions.
8. **Limited preprocessor use** — limit to file inclusion and simple macros.
9. **Limited pointer complexity** — max 2 levels of dereferencing.
10. **Compiler warnings + static analysis** — compile with all warnings enabled; use static analysis tools.

.. note::

   **Rules 3 and 9 are already implemented**, as ``BRULE-060`` (no dynamic
   memory allocation after initialisation) and ``BRULE-065`` (no excessive
   pointer indirection) in ``src/rules/brules/``. They are the only non-CERT-C
   rules SqC ships, and they are enabled through
   ``src/rules/brules/rules-all.toml`` rather than the CERT C manifests. The
   rest of the Power of Ten remains a candidate: rules 1, 2, 4, 6 and 8 are
   plausibly checkable with the AST and CFG infrastructure already here, while
   5 (assertion density) and 10 (build flags) are not really analyzer rules at
   all.

JPL Institutional Coding Standard (2009)
=========================================

Based on MISRA-C:2004 and the Power of Ten rules, the JPL standard also
addresses multi-threaded software risks that neither of those covered.

Multi-threading / Concurrency
-----------------------------

- Use IPC messages for task communication; avoid callbacks.
- Task synchronisation shall not be performed through task delays.
- Data objects in shared memory should have a single owning task with explicit ownership transfer.
- Avoid semaphores/locks; if used, avoid nested use.
- Use memory protection, safety margins, and barrier patterns.

Other Key Rules
---------------

- No selective value assignments to elements of an enum list (except first or all).
- Use typedefs that indicate size and signedness (``I32``, ``U16``, etc.) instead of basic types.
- Make order of evaluation in compound expressions explicit with parentheses.
- Boolean expressions shall have no side effects.
- No more than two levels of indirection per declaration.
- Do not hide dereference operations in macros or typedefs.
- Non-constant function pointers should not be used.

Earlier Standards Referenced by JPL
-----------------------------------

The JPL standard consulted numerous earlier standards including:

- Spencer's 10 Commandments (1991)
- Nuclear Regulatory Commission (1995) — 22 rules
- Original MISRA rules (1997)
- Software System Safety Handbook (1999) — 34 rules
- European Space Agency coding rules (2000) — 123 rules
- Goddard Flight Software Branch coding standard (2000) — 100 rules

BARR-C Embedded C Coding Standard
===================================

Barr Group's standard minimises bugs in firmware by focusing on practical rules.
BARR-C:2018 has been fully harmonised with MISRA C:2012 in its stylistic rules.
Key embedded-specific areas:

- Proper use of the ``volatile`` keyword for hardware registers and ISR-accessed variables.
- File naming and organisation conventions.
- Comment standards.
- Specific brace placement rules selected to reduce bugs.

Candidate Rules for Implementation
====================================

Core Safety Rules (Pre-MISRA)
-----------------------------

- No dynamic memory allocation after initialisation
- No recursion
- Fixed upper bounds on all loops
- No ``goto``, ``setjmp``, ``longjmp``
- Check all function return values
- Check function parameter validity
- Use assertions liberally (2+ per function)
- Limit function size (~60 lines max)
- Limit function parameters (~6 max)
- Limited pointer complexity (2 levels max)

Embedded-Specific Rules
-----------------------

- Use sized types (``uint32_t``, ``int16_t``) not ``int``/``short``/``long``
- Proper use of ``volatile`` keyword
- No non-constant function pointers
- Memory barriers and safety margins
- Limited preprocessor use (no token pasting, no variadic macros)
- Explicit order of evaluation (use parentheses)
- No side effects in boolean expressions
- Smallest possible scope for all declarations

Multi-threading Safety (JPL-specific)
-------------------------------------

- IPC-based task communication (not shared memory)
- No task delays for synchronisation
- Single-owner model for shared data
- Avoid or strictly control semaphore use
