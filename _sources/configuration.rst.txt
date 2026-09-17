Configuration
=============

Manifest File
-------------

The rules manifest TOML file controls which rules are active and their severity.
The default manifest (``rules_templates/rules-all.toml``) enables |rules_enabled| of the |rules_total| tracked rules.
The other |rules_disabled| are tracked but not implemented — see `Tracked but not implemented`_ below.

::

    # Use default (all rules enabled)
    aurora-lint /path/to/code

    # Use a custom manifest
    aurora-lint --manifest my-rules.toml /path/to/code

Custom Manifest Format
----------------------

.. code-block:: toml

    [metadata]
    name = "My Project Rules"
    version = "1.0.0"
    description = "Custom CERT C rules for my project"
    cert_version = "2016"

    [rules.ARR30-C]
    enabled = true
    severity = "High"
    description = "Do not form or use out-of-bounds pointers or array subscripts"
    category = "Rule"
    cert_id = "ARR30-C"

    [rules.STR31-C]
    enabled = false  # Disable this rule
    severity = "Medium"
    description = "Guarantee that storage for strings has sufficient space"
    category = "Rule"
    cert_id = "STR31-C"

Supported CERT C Rules
----------------------

|rules_total| rules are tracked across 17 categories; |rules_enabled| are implemented and enabled by
default (the remaining |rules_disabled| are tracked but not implemented — see
`Tracked but not implemented`_ below):

==========  ======  ===========================================================
Category    Count   Rules
==========  ======  ===========================================================
**API**     9       API00-C through API10-C (selected)
**ARR**     9       ARR00-C through ARR39-C (selected)
**CON**     23      CON01-C through CON50-C (selected)
**DCL**     31      DCL00-C through DCL41-C (selected)
**ENV**     8       ENV01-C through ENV34-C (selected)
**ERR**     11      ERR00-C through ERR34-C (selected)
**EXP**     31      EXP00-C through EXP47-C (selected)
**FIO**     35      FIO01-C through FIO51-C (selected)
**FLP**     13      FLP00-C through FLP37-C (selected)
**INT**     23      INT00-C through INT36-C (selected)
**MEM**     17      MEM00-C through MEM36-C (selected)
**MSC**     10      MSC04-C through MSC41-C (selected)
**POS**     20      POS01-C through POS54-C (selected)
**PRE**     16      PRE00-C through PRE32-C (selected)
**SIG**     7       SIG00-C through SIG35-C (selected)
**STR**     16      STR00-C through STR38-C (selected)
**WIN**     6       WIN00-C through WIN30-C (selected)
==========  ======  ===========================================================

For the full list, see ``rules_templates/rules-all.toml`` or the rule source files
in ``src/rules/cert_c/``.

Strict vs. Relaxed Onboarding
-----------------------------

Dropping aurora-lint into CI/CD against an existing codebase for the first
time can surface a large number of findings before you have had a chance to
triage any of them — real-world precision varies a lot by codebase (see
``docs/tool-comparison.rst`` for measured figures). Two
things help without writing a manifest at all:

- ``--min-severity``/``--fail-on-severity`` (see `Getting Started
  <../README.md#getting-started>`_ in the top-level README) filter what is
  printed and what fails a build, independent of the manifest.
- ``--exclude`` drops vendored code, generated files, and test harnesses
  from the scan entirely — usually the single biggest volume reduction on a
  first run.

For a coarser starting point than either of those, build your own
**relaxed** manifest the same way this project's own real-world benchmark
suite builds one per codebase (``conf/realworld/*-rules.toml`` — read
``conf/realworld/README.md`` for the full discipline, summarized here):

1. Start from ``rules_templates/rules-all.toml`` (the **strict** default —
   this is the same file aurora-lint embeds and ships) and copy it as your
   starting point, rather than writing a manifest from scratch.
2. Disable a rule wholesale only for one of two reasons, each recorded as a
   comment on its ``enabled = false`` line: it is **categorically
   inapplicable** to your codebase (a Windows-only rule on a POSIX-only
   project, ``FIO*`` on a library with no file I/O), or you are
   **deliberately deferring it** while your team builds up triage capacity,
   with a plan to turn it back on.
3. **Do not disable a rule just because it looks "advisory" or "style," and
   do not disable one on a first impression of noise without measuring
   it first.** This project shipped exactly that manifest once — thirteen
   rules turned off across seven codebases on an "advisory/style" label —
   and measuring the two codebases that kept them found six of the
   thirteen were the *best-precision* rule group in the whole suite. All
   thirteen run everywhere again. A rule that looks noisy on unfamiliar
   code is common; a rule that is actually low-value on *your* code is a
   claim worth checking against your own findings before it goes in a
   manifest, not before.

**There is no single relaxed manifest shipped today**, and that is a
deliberate gap rather than an oversight: real-world noise is measurably
project-dependent (that is the whole reason ``conf/realworld/*.toml`` files
do not inherit from a shared base), so a one-size-fits-all "these rules are
noisy" list would risk the exact mistake above on whichever project doesn't
match its assumptions. A data-driven relaxed starter, generated from
aggregate real-world precision across this project's own benchmark corpus
rather than hand-picked, is tracked as a follow-up (aurora_lint task 1179's
companion) rather than shipped speculatively here.

Tracked but not implemented
----------------------------

|rules_disabled| of the |rules_total| tracked rules have a rule directory and a manifest entry but no
detection logic (no ``.rs`` file). This is a deliberate policy, not a gap:
aurora-lint does not implement against incomplete CERT-C rule content, since there is
ample well-established work to do and a stub implementation would mean
inventing a rule CERT itself has not written.

Two are parked on upstream CERT publishing real content for the rule:

- **ENV04-C** — *Protect programs whose behavior can be controlled by
  environment variables*. CERT's page carries only OpenMP environment-variable
  framing; severity, likelihood, priority and level are all unscored, and
  there is no formal description, no compliant/noncompliant examples, and no
  CWE mapping. `CERT wiki page
  <https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/recommendations/environment-env/env04-c>`_.
  Will be implemented once CERT ships real content; tracked as a gate task
  until then.
- **MSC25-C** — *Do not use insecure or weak cryptographic algorithms*.
  CERT's scraped description is the single sentence "This rule is a stub,"
  with zero CWE references. `CERT wiki page
  <https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/recommendations/miscellaneous-msc/msc25-c>`_.
  Will be implemented once CERT ships real content; tracked as a gate task
  until then.

The other two are ordinary backlog — CERT's content for them is complete, they
are simply not yet written:

- **MSC18-C** — CERT's description and risk assessment are complete (severity
  Medium, 7 CWE references), and one ``pass`` fixture is already staged.
- **MSC19-C** — CERT's description and risk assessment are complete
  (severity Low), and 2 ``fail`` + 2 ``pass`` fixtures are already staged —
  the closest of the 4 to being implementable.
