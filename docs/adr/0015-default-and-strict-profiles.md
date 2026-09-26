# 0015. Policy and environment are separate settings; `default` and `strict` are presets over them

## Status

Accepted (Brandon, 2026-09-25).

## Context

The labeling ADRs aim at one consistent answer to every question. Applied at
full strictness, some of those answers make a rule noisy enough that a team
turns it off, and then it catches nothing. Three cases showed it:

- **Asserts.** ADR-0010 treated an `NDEBUG`-strippable `assert` as no guard,
  because the release build removes it. That's the reading MISRA-style and
  certified embedded code needs. But every mainstream analyzer surveyed (the
  Clang Static Analyzer, Polyspace, Coverity's models) treats a live assert as
  an assumption, CERT's own EXP34-C compliant solution uses one, and the
  strict reading has been called too harsh every time it came up. It flags a
  dereference the programmer explicitly asserted non-NULL.
- **Dependent sites.** When a caller dereferences a pointer unchecked and a
  callee dereferences it again, both lines violate the rule. Reporting both
  counts one missing check twice.
- **The standard library.** ISO C and POSIX specify, for example, that
  `free(NULL)` does nothing. A minimal libc for a small embedded target may
  drop that check to save memory, so safety-critical code can't rely on it.

Each has a defensible strict answer and a defensible everyday answer. Forcing
one answer on everyone either buries the average user in noise or leaves the
safety-critical user unprotected.

## Decision

1. **Two separate axes, never folded into one switch.**
   - **Policy** says what the rules require of the code: which findings are
     reported. It's the axis the assert question and the dependent-site
     question live on.
   - **Environment** says what the analyzer believes about the platform the
     code runs on: which library contracts hold. It's the axis the
     `free(NULL)` question lives on.
   An embedded team on newlib, which honors `free(NULL)`, can still want the
   strict policy. A desktop team behind a nonconforming allocator shim wants
   the default policy and a distrusted environment. One switch can't express
   either.
2. **Policy has two settings.**
   - **`default`**, for the average codebase: a dominating assert whose
     condition establishes the property is a guard, strippable or not (the
     assumption the analyzers above make); in a proof chain, only the first
     failing site is reported; a function declared `_Noreturn` (ISO C) is
     trusted not to return; and the rule-specific relaxations the tool's
     option list names (Decision 7).
   - **`strict`**, for safety-critical, MISRA-like and certified code: a
     strippable assert guards nothing; every violating line is reported;
     only a body verified never to return proves noreturn.
   In both, a violation inside an assert's argument is reported, and an
   assert macro no configuration strips, whose failure path never returns, is
   a guard.
3. **Environment is declared, never inferred.**
   - `hosted` (the default) trusts the ISO C and POSIX library contracts,
     such as `free(NULL)` doing nothing (ADR-0011 basis 1).
   - `freestanding` trusts no library semantics beyond the language (C11
     freestanding implementations guarantee only a few headers).
   - A `libc` model (for example glibc, musl, newlib, picolibc, or custom)
     selects a contract table, and per-contract overrides cover in-house
     libraries (for example `free_null_is_noop = false`).
   - Some **language** guarantees also rest on the environment behaving as
     the standard requires. Static storage is zeroed before `main` (C11
     6.7.9p10) only if the startup code does it: bare-metal startup that
     skips clearing `.bss` is nonconforming but real. `main`'s `argv`
     guarantees (C11 5.1.2.2.1) hold only in a hosted environment. So
     `freestanding` drops the hosted-only ones, and an override such as
     `static_zero_init = false` covers nonconforming startup. Then reading a
     static with no initializer is a use of an indeterminate value (EXP33-C).
   A declared environment is the user's own configuration (ADR-0001). The
   analyzer never guesses it from the host that runs the scan (ADR-0011
   basis 4).
4. **`default` and `strict` are named presets over both axes**, not the axes
   themselves:
   - the **default** preset is `policy = default`, `environment = hosted`;
   - the **strict** preset is `policy = strict`, `environment = freestanding`,
     for teams that trust nothing;
   - any combination can be set explicitly, for example strict policy on a
     hosted newlib target.
5. **The oracle is independent of both axes.** It records the strict,
   freestanding truth for each line (ADR-0014), plus a tag on every row a
   relaxation affects: assert-dominated, dependent site, or library-contract
   trust (naming the contract). Any setting's figures are computed from the
   same oracle. A rule-specific relaxation (Decision 7) adds its own tag.
   **Published benchmark figures use the ISO C and POSIX contract
   model**, never one libc's extensions, so they don't depend on the host
   (ADR-0011).
6. **Everything else is the same in every setting.** ADR-0011's rejected
   bases stay rejected: compiler and platform behavior the user hasn't
   declared, inference, and in-tree caller sets of anything publicly
   callable. So do ADR-0010 (every configuration counts), ADR-0006 (identify
   before judging) and ADR-0005 (misfires are bugs).
7. **Every relaxation is a named option, and the tool's list of options is
   the record** (amended 2026-09-25, Brandon).
   - **Cross-cutting relaxations** (asserts, dependent sites, `_Noreturn`)
     apply to many rules. Adding one requires an amendment to this ADR.
   - **Rule-specific relaxations** apply to one rule's checkable form. For
     example, FLP00-C's default policy doesn't report a floating-point
     comparison with exact zero, which Polyspace also exempts unless asked
     not to. These don't amend this ADR one by one.
   - **Either kind** needs evidence that mainstream analyzers make the same
     assumption, an oracle tag, and its own setting with its value under each
     preset, validated like rule behavior.
   - **Adding an environment contract** requires a citation to the standard
     or to the library's documentation.
   - **The record:** the tool lists every policy and environment option it
     supports, with each preset's value. The documentation is generated from
     the same table, so it can't disagree with the tool. That list is the
     complete record of what the default preset relaxes.
   - Removing noise any other way is suppression or configuration
     (ADR-0001).
8. **Every figure names its setting.** Published results report the default
   preset as the headline, with strict alongside. Juliet is run under both.

## Consequences

- ADR-0001's "report as written" describes the strict policy. The default
  policy is a deliberate, documented subset of it, and never a hidden one.
- ADR-0010 Decision 5 describes both policies (amended with this ADR).
- Oracle rows affected by a relaxation need their tags before default figures
  can be computed from the oracle.
- A team can start with the default preset and tighten either axis without
  the rules meaning something different: the same violations, fewer
  assumptions.
- MISRA-style and certified users get the reading their standards expect
  (MISRA C's run-time-failure directive; the defensive-implementation
  techniques ISO 26262, IEC 61508 and DO-178C recommend). Everyone else gets
  the reading mainstream tools use.
