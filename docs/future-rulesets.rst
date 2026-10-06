==============================
Future Rulesets Beyond CERT C
==============================

This page documents embedded coding standards and rule families that predate or
complement MISRA and could be added to aurora-lint in the future. All listed rules are
freely implementable — they come from open/public-domain standards.

Why CERT C Is The Base Standard
================================

Everything below is framed as complementing MISRA, which only makes sense once
you know why MISRA is not what aurora-lint implements. It is a fit-to-domain choice,
not a fallback:

- **CERT C is open.** Public and freely implementable, so every rule aurora-lint
  enforces can be read and checked against the analyzer's behavior. That is
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
  body. aurora-lint does not implement that apparatus. That is a statement about what
  aurora-lint is and not about who should use it — nothing here is domain-restricted,
  and C written for automotive, medical or aerospace is subject to these rules
  like anyone else's.

So the question this page answers is not "what would we add if we could afford
MISRA" but "which open standards add coverage CERT C does not already give
us". Two rules from the JPL lists below are already implemented — see the
note under The Power of 10 Rules below.

The Power of 10 Rules (NASA JPL, 2006)
=======================================

Created by Gerard J. Holzmann at NASA's Jet Propulsion Laboratory, these 10
rules eliminate C coding practices that make code difficult to review or
statically analyze. Holzmann presents them as a deliberately short set that
a tool can check mechanically, in contrast to guidelines of a hundred rules
or more; the JPL standard below later combined them with MISRA-C:2004.

1. **Restrict control flow** — no ``goto``, no ``setjmp``/``longjmp``, and no recursion, direct or indirect.
2. **Fixed loop bounds** — all loops must have fixed upper bounds (prevents runaway code).
3. **No dynamic memory after init** — all allocation happens during initialization, none after it.
4. **Function size limits** — no function longer than ~60 lines (one printed page).
5. **Assertion density** — average at least two assertions per function.
6. **Limited scope** — each data object lives in the innermost scope that can hold it.
7. **Check return values** — check the return value of all non-void functions.
8. **Limited preprocessor use** — limit to file inclusion and simple macros.
9. **Limited pointer use** — at most one level of dereferencing, no dereference hidden in a macro or typedef, and no function pointers.
10. **Compiler warnings + static analysis** — compile with all warnings enabled; use static analysis tools.

.. note::

   **Rule 3 is already implemented**, as ``BRULE-060`` (no dynamic memory
   allocation after initialization) in ``src/rules/brules/``. Next to it,
   ``BRULE-065`` (no excessive pointer indirection) flags a declaration with
   more than two levels of pointer indirection. That is the JPL standard's
   threshold (D-60411 Rule 26, from MISRA-C:2004 Rule 17.5), not rule 9's
   stricter one level. They and the CWE ruleset (``src/rules/cwe/``) are the
   only non-CERT-C rules aurora-lint ships. They are enabled through
   ``src/rules/brules/rules-all.toml`` rather than the CERT C manifests,
   while the CWE ruleset is part of the default manifest. The
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

Paraphrased; the rule numbers are D-60411's.

- Tasks talk to each other through IPC messages, not callbacks (Rule 6).
- No task waits out a delay as a way to synchronize with another (Rule 7).
- Each shared data object has one owning task, and ownership is handed over explicitly (Rule 8).
- Semaphores and locks are best avoided; where they are used, not nested, or else always taken in one documented order (Rule 9).
- Memory protection where the operating system offers it; otherwise safety margins and barrier patterns that expose access violations (Rule 10).

Other Key Rules
---------------

- An enumerator list sets explicit values on its first member only, or on every member (Rule 12).
- Fixed-width typedefs that name their signedness, such as ``I32`` and ``U16``, stand in for the basic types (Rule 17).
- Parentheses spell out the intended evaluation order in compound expressions (Rule 18).
- Evaluating a Boolean expression changes no state (Rule 19).
- A declaration carries at most two levels of pointer indirection (Rule 26).
- Macros and typedefs never conceal a pointer dereference (Rule 28).
- Any function pointer is constant (Rule 29).

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

Barr Group says its standard "was developed to minimize bugs in firmware by
focusing on practical rules that keep bugs out", and that in BARR-C:2018 "the
stylistic coding rules have been fully harmonized with MISRA C: 2012"
(barrgroup.com, *Embedded C Coding Standard*).

Candidate Rules for Implementation
====================================

Core Safety Rules (Pre-MISRA)
-----------------------------

- No dynamic memory allocation after initialization
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
- No task delays for synchronization
- Single-owner model for shared data
- Avoid or strictly control semaphore use
