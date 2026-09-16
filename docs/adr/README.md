# Architectural Decision Records

Settled policy questions about aurora-lint's fundamental behavior — the ones
that keep coming back up as "should we change this?" across independent
sessions and nodes. An ADR exists to stop that re-litigation: read the
relevant one before proposing to change a rule's core behavior, disable a
rule, or reinterpret what a benchmark result means.

Not in the Sphinx toctree, same as `docs/design/` — read directly.

## When to write one

When a question gets settled that isn't obvious from the code, isn't already
written in `docs/`, and is likely to be asked again by a different session
that lacks this conversation's context. Task-DB notes and commit messages are
for a specific piece of work; an ADR is for a standing policy that should
outlive any one task.

## Format

`NNNN-short-slug.md`, sequential, never renumbered or deleted. Each file:

- **Status** — Accepted (the only status in use so far; a future ADR may
  supersede an earlier one, but the earlier one stays as the historical
  record with a note pointing to its replacement, not edited in place).
- **Context** — what prompted the question, in enough detail that the
  decision doesn't look arbitrary.
- **Decision** — the rule, stated so it can be applied without re-deriving
  the reasoning.
- **Consequences** — what this does and doesn't justify, concretely enough
  to catch someone about to misapply it.

## Index

- [0001 — Rules report violations as written; suppression/config is where
  codebase-specific judgment belongs](0001-report-as-written-suppression-is-configuration.md)
- [0002 — A 0% real-world true-positive rate doesn't mean a rule is broken or
  unneeded](0002-zero-real-world-tp-does-not-imply-rule-unneeded.md)
- [0003 — New reusable capability defaults to the utility layer; promote to
  `lang_parsing_substrate` only when genuinely cross-language](0003-utility-layer-vs-substrate.md)
- [0004 — Postgres is the single source of truth for published data; local
  storage is working data only](0004-postgres-is-the-single-source-of-truth.md)
- [0005 — Distinguish misfires from judgment false positives; only the
  former is always a rule bug](0005-misfires-vs-judgment-false-positives.md)
- [0006 — Resolve an identifier to its declaration; a name is not a
  variable, and a struct tag is not a
  type](0006-resolve-identifiers-to-declarations.md)
- [0007 — A disclosure becomes part of the published record only once it has
  landed upstream](0007-responsible-disclosure-gates-publication.md)
