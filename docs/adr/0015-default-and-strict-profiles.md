# 0015. Policy and environment are separate settings; `default`, `strict` and `pedantic` are presets over them

## Status

Accepted (Brandon, 2026-09-25).

## Context

The labeling ADRs aim at one consistent answer to every question. Applied at
full strictness, some of those answers make a rule noisy enough that a team
turns it off, and then it catches nothing. Three cases showed it:

- **Asserts.** ADR-0010 treated an `NDEBUG`-strippable `assert` as no guard,
  because the release build removes it. That's the reading safety-critical
  coding standards take: a check protects only when its failure leads to an
  explicit recovery action in the deployed code. But every mainstream
  analyzer surveyed (the Clang Static Analyzer, Polyspace, Coverity's
  models) treats a live assert as an assumption, CERT's own EXP34-C
  compliant solution uses one, and the strict reading has been called too
  harsh every time it came up. It flags a dereference the programmer
  explicitly asserted non-NULL.
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

   **Build facts improve results and are never required** (amended
   2026-09-30, Brandon). A build fact is anything a build knows that the
   source files alone don't say: a compile database's include paths and
   `-D` macros, declared allocators and deallocators, a declared closed
   program, which files make up the scan, and any later input of the same
   kind.
   - **Improve, never depend.** Every build fact is optional. With none
     declared, each rule takes its strict reading: no credit the source
     alone can't prove. A declaration may add or remove findings; its
     absence costs precision, and never gives credit the source doesn't
     support.
   - **Declared, never inferred.** A build fact comes from the project's
     own statement: a setting, a flag, or a build file the user passes. The
     tool never infers one from the host, from build output it finds in
     the tree, or from a guess. It doesn't go looking for a
     `compile_commands.json` it wasn't given.
   - **Derive from source structure where possible.** A fact the source
     establishes needs no declaration: each `.c` file is a translation
     unit, and a quoted `#include` of a header beside the including file
     resolves without `-I`. A build file may refine such a fact, but is
     never the only way to get it.
   - **Kept honest by tests with no build inputs.** Every rule fixture runs
     with no compile database and no declarations, under both presets.
     Each build fact must be tested both declared and absent.
4. **`default` and `strict` are named presets over both axes**, not the axes
   themselves:
   - the **default** preset is `policy = default`, `environment = hosted`;
   - the **strict** preset is `policy = strict`, `environment = freestanding`,
     for teams that trust nothing;
   - any combination can be set explicitly, for example strict policy on a
     hosted newlib target.

   **Presets enforce; facts describe the target** (amended 2026-10-03,
   Brandon). Two different things configure a scan.
   - A **preset** (`default`, `strict`) is a decision about rule
     enforcement. `strict` applies the rules as written (ADR-0001) with full
     pedantry; `default` applies a reasonable relaxation grounded in how C is
     typically built and used. Presets are values of the policy and
     environment axes. The `[environment]` section holds two different
     things that do not collide: the hosted or freestanding `kind`, which a
     preset picks as a trust choice about the library, and the target facts
     below, which a preset never sets.
   - **Facts** describe the target the code is built for: the integer data
     model and type sizes, the width of `wchar_t`, whether plain `char` is
     signed, and in future the language edition, library groupings such as
     POSIX, and alignment. Facts are optional context, like a compilation
     database. None is required, and each has a stated default: the ISO C
     guarantee, or unknown. A project that knows its target declares them, so
     that findings that would otherwise be noisy or wrong become precise.
     aurora-lint does not compile the code, but knowing what a compiler would
     know about the target improves its rule decisions.
   - A **data model** (`iso`, `ilp32`, `lp64`, `llp64`) is a named bundle of
     facts, not an enforcement preset. A project may override any fact key by
     key. Precedence is the command line, then the project's keys, then the
     bundle of the data model named in the same configuration, then the ISO
     minimum. A key that only repeats the value of the bundle its own
     configuration names declares nothing. A fact no bundle or key sets is
     unknown and receives only the ISO C guarantee.
   - Every declared fact is part of the settings hash. The run label names
     only the enforcement preset (Decision 8).
5. **The oracle is independent of both axes.** It records the strict,
   freestanding truth for each line (ADR-0014), plus a tag on every row a
   relaxation affects: assert-dominated, dependent site, or library-contract
   trust (naming the contract). Any setting's figures are computed from the
   same oracle. A rule-specific relaxation (Decision 7) adds its own tag.
   **Published benchmark figures use the ISO C and POSIX contract
   model**, never one libc's extensions, so they don't depend on the host
   (ADR-0011).

   **Tags follow the tool; they never lead it** (amended 2026-10-02,
   Brandon). A tag marks a row that an option already in the tool's list
   (Decision 7) relaxes, and only within that option's stated scope. A case
   that merely resembles a relaxed one keeps its strict verdict, untagged —
   for example, a project function shaped like a library function that a
   contract covers. A new relaxation is added in this order: first the named
   option in the tool, then its tag, then the affected rows relabeled. The
   oracle is never reinterpreted so that a default figure reads as a
   relaxation would make it read. The oracle is the oracle, independent of
   the tool (ADR-0014): relaxation happens in the tool, never in the oracle.
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
   A run whose settings are a preset plus a declared environment fact is
   named after both, as `-default+closed-{hash12}` and
   `-strict+closed-{hash12}` for a scan declared a closed program, never a
   bare `-preset-`, so the default and strict runs of one build stay distinct.

   **Labels name the preset, not the facts** (amended 2026-10-02, Brandon).
   A run id names the preset, as `-default-{hash12}` or `-strict-{hash12}`.
   The settings hash identifies every declared fact, and the full resolved
   settings are recorded with the run, so labels do not enumerate facts: they
   would grow with every new setting. The existing `+closed` token stays,
   because removing it would rename existing runs, but no further facts are
   added to labels. A published figure names its settings in its text or
   caption, from the recorded settings, not from the run id.

## Consequences

- ADR-0001's "report as written" describes the strict policy. The default
  policy is a deliberate, documented subset of it, and never a hidden one.
- ADR-0010 Decision 5 describes both policies (amended with this ADR).
- The README's "no build system required" claim rests on Decision 3's
  build-fact clause. A change that would make any build fact required, or
  infer one, needs an amendment to this ADR first.
- Oracle rows affected by a relaxation need their tags before default figures
  can be computed from the oracle.
- A team can start with the default preset and tighten either axis without
  the rules meaning something different: the same violations, fewer
  assumptions.
- Safety-critical and certified users get the reading safety-critical
  coding standards take: a check counts as protection only when its failure
  leads to an explicit recovery action in the deployed code (JPL's Power of
  Ten, Rule 5; JPL D-60411, Rule 16), and C lets `NDEBUG` remove
  `assert` entirely (C11 7.2p1). Everyone else gets the reading mainstream
  tools use.

## Amendment (2026-10-07, Brandon): a third preset, and how each preset reads a rule's text

### Decision

1. **One axis, centered on the rule's text.** For each rule, the presets
   are readings of its text, in order:
   - **cut, too loose:** the only checkable form needs the programmer's
     intent, so no preset can enforce it;
   - **`default`:** a documented disagreement with the text in the relaxed
     direction. It may narrow a rule to the conditions where its findings
     are useful in everyday code. Every narrowing is a named option
     (Decision 7).
   - **`strict`:** the rule as written, for any ruleset. It accepts the
     false positives that follow from enforcing the text, and declares the
     imprecision where the text cannot be checked exactly.
   - **`pedantic`:** a documented disagreement in the stricter direction:
     a sound over-approximation of the text, or a stricter rule backed by
     an established standard (for example, a construct ban that a MISRA
     rule states). A pedantic form must still be enforceable.
   - **cut, too strict:** a form that reports every instance of a
     construct with no checkable violation behind it.
   A rule past either end is not enforced in any preset.
2. **The presets are not nested.** Any preset may take a rule out of play.
   A strict-only rule is legitimate: out under `default` because it is too
   noisy for everyday use, out under `pedantic` because it cannot meet the
   sound standard. Pedantic may decline a rule rather than run a weaker
   form of it.
3. **A list in a rule's text is authoritative as written,** even when the
   text calls it open ("such as", "for example"). `strict` may extend it
   only with other authoritative material that bounds it better (for
   example, POSIX's list of async-signal-safe functions read with a CERT
   rule that names some of them). `pedantic` may hold to the listed items
   alone.
4. **The oracle stays at `strict`.** A CERT C oracle labels each rule as
   written, by definition (ADR-0014). `default` and `pedantic` are scored
   as differences from it: where either disagrees with the oracle, that is
   a documented move of the enforcement boundary, justified by the option
   or reading that makes it, and not an ordinary false positive or false
   negative. Each rule record states whether its verdict differs by preset,
   and the preset test matrix covers only those rules.
5. **The axis is not specific to CERT C.** The CWE ruleset, and any later
   ruleset, is read the same way around its own text.

### Rationale

- **Presets as approximations of a specification.** Let V(R) be the set of
  program points that violate rule R's text, and A the set a preset
  reports. `strict` aims at A = V(R). `pedantic` aims at V(R) ⊆ A, the
  relation a sound abstract interpretation keeps (Cousot and Cousot,
  "Abstract Interpretation: A Unified Lattice Model for Static Analysis of
  Programs by Construction or Approximation of Fixpoints", POPL 1977), or
  at a stricter specification V′ ⊇ V(R). `default` aims at A ⊆ V(R), the
  under-approximation that "can prove the presence of bugs but not their
  absence" (O'Hearn, "Incorrectness Logic", Proceedings of the ACM on
  Programming Languages, 2020), or at a narrower
  specification. Each preset is a partial function on rules: it gives a
  checking predicate, or declines the rule. A partial function that may
  decline independently in each preset is why the presets are not nested.
- **Why the cuts exist.** Every non-trivial property of a program's
  behavior is undecidable (Rice, "Classes of Recursively Enumerable Sets
  and Their Decision Problems", Transactions of the AMS, 1953), so each
  preset enforces a checkable approximation of the text, never the text
  itself. A rule is cut where no checkable approximation exists, because
  only intent separates the compliant code from the noncompliant, or where
  the only checkable form reports a construct rather than a violation.
- **Declining is two different things.** A preset declining a rule is a
  decision about the rule, made once. Withholding a verdict on one program
  point, because a fact the rule needs was not declared, is a decision
  about that program; it is the reject option of selective classification,
  where a classifier's risk (its loss on the cases it accepts) is reported
  against its coverage (the share it accepts) (El-Yaniv and Wiener, "On the
  Foundations of Noise-free Selective Classification", JMLR 2010; Geifman
  and El-Yaniv, "Selective Classification for Deep Neural Networks",
  NIPS 2017). The two are scored separately.
- **The list principle and the canons of construction.** Reading a rule's
  list as closed matches the canon "the expression of one thing implies
  the exclusion of others" (expressio unius); reading POSIX together with a
  CERT rule that cites it matches the canon that texts on the same subject
  are read as one (in pari materia). Both canons are described in
  Brannon, "Statutory Interpretation: Theories, Tools, and Trends",
  Congressional Research Service report R45153, 2023. Decision 3 goes further than the
  canons in one respect, and does so deliberately: the canon *ejusdem
  generis* would extend an open list ("such as") to items like the listed
  ones. Judging likeness needs the kind of intent a checker cannot read,
  so `strict` closes the list and leaves extension to authoritative
  material.

### Points this amendment does not settle

These earlier statements read differently under the amendment. They are
recorded here and left unchanged until decided:

- Decision 4's 2026-10-03 amendment says `strict` applies the rules as
  written "with full pedantry". This amendment separates the text
  (`strict`) from readings beyond it (`pedantic`).
- Decision 4 bundles `environment = freestanding` into the strict preset,
  and Decision 5 has the oracle record the "strict, freestanding truth".
  Whether distrusting the library is the text (`strict`) or a reading
  beyond it (`pedantic`) is open; ADR-0011's Consequences already speak of
  "a strict or pedantic mode that trusts no library behavior". The
  environment value of the `pedantic` preset is also open.
- Decision 2 and ADR-0010 Decision 5 make a strippable assert no guard
  under `strict`, citing C11 7.2p1 and CERT MSC11-C. Whether that is a
  rule's text or a reading beyond it is to be settled rule by rule.
- The Consequences say the default policy is "a deliberate, documented
  subset" of the strict one, with "the same violations, fewer
  assumptions". Under Decision 2 of this amendment the presets are not
  nested.
- Decision 8's run labels name only `-default-` and `-strict-`; a
  `pedantic` run needs its own label.

