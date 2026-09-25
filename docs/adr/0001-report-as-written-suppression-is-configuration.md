# 0001. Rules report violations as written; suppression/config is where codebase-specific judgment belongs

## Status

Accepted

## Context

Rule behavior is periodically challenged with framing like "this fires on an
idiom that's clearly intentional here" or "this doesn't make sense given how
this codebase is structured." A real, high-volume, FP-*looking* pattern on
one specific project feels like it should change the rule. That instinct
conflates two different questions:

1. Is the rule **correct** — does every reported finding genuinely match what
   the rule's text (CERT's, as aurora-lint interprets it) describes?
2. Is the rule **wanted** — does a specific team, on a specific codebase,
   want to act on every instance of what the rule correctly detects?

Softening a rule's detection logic to answer (2) breaks (1) for every other
codebase the rule runs against. A rule that under-reports to avoid noise on
one project is failing at its one job everywhere else.

## Decision

aurora-lint's job is to correctly surface every violation of a rule as the
rule is written — not to guess which violations a given team will care
about, and not to bend detection logic to accommodate a particular
codebase's architecture or house style.

Both kinds of noise get handled downstream, per project, by that codebase's
own maintainer, never inside the rule:

- **Inline suppression** (`AURORA-SUPPRESS`, hash-pinned to the line) for a
  specific instance with a justification.
- **Per-project rule manifests** (`conf/realworld/*-rules.toml`, and a user's
  own config) to disable a rule wholesale for a codebase where it is
  categorically inapplicable, with one of the three documented reasons.

This is already implemented and enforced — see `docs/suppression.rst`
("Design intent: surface, don't silence") and `conf/realworld/README.md`.
This ADR is the record of *why* that split exists, so it doesn't need
re-deriving every time a rule looks noisy on one project.

## Consequences

- A rule fix changes detection logic only to make the rule **more correct**
  against its own written definition — fewer findings that don't actually
  match what the rule describes, more that do. It never suppresses a
  category of genuinely-matching findings because they're unwanted on a
  specific codebase.
- "This fires on legitimate code on project X" is a signal to check
  `conf/realworld/X-rules.toml` or file a suppression — not a signal to
  weaken the rule for everyone.
- The one real exception: the finding doesn't actually match what the rule's
  text describes at all (wrong AST node, wrong operand, misattributed line,
  a check that never encodes real semantics). That's a detection bug, and
  fixing it belongs in the rule. See ADR-0002 for the related question of
  when a rule's poor real-world hit rate is itself evidence of exactly this
  kind of bug versus evidence of nothing.
- What may prove a flagged construct safe, in a rule or in a label (language
  guarantees and the scanned source yes, compiler behavior and inference no),
  is set out in ADR-0011.
