# Contributors

SqC is developed at [BISSELL](https://www.bissell.com/). Listed by role rather
than by commit count — the counts below say who was involved and when, which
they establish well, and not how much each contribution was worth, which they
do not. 85 commits that create a working analyzer from nothing are not
commensurable with 85 commits of refinement.

## Principal authors

Both are named in `Cargo.toml`'s `authors` field.

**Eric Buehler** — originator and founding principal author. Created SqC and
did the initial lifting (Sep–Nov 2025, 85 commits), and has directed the work
throughout. The tool exists, and continues to be pursued, because of that
direction.

**Brandon Arrendondo** — primary contributor and maintainer. Has driven
productionalization since Nov 2025 (1,540 commits): rule implementation,
false-positive reduction, the benchmark and ground-truth oracle
infrastructure, packaging and documentation.

## Contributors

**Tristan VanFossen** — second heaviest contributor (Nov–Dec 2025, 337
commits). Also the author of [clew](https://github.com/tvanfossen/clew), the
symbol-graph indexer SqC uses for code navigation — an ongoing dependency, not
only a past contribution.

The following contributed during a focused team effort in November 2025, which
doubled as the group's hands-on introduction to working with Claude:

- **Jason Parker** (79 commits)
- **Blake Azuela** (55 commits)
- **Ally DeYoung** (28 commits)
- **Huu Nguyen** (21 commits)

## AI assistance

SqC was developed with substantial assistance from
[Claude](https://claude.ai) (Anthropic) — code generation, rule
implementation, false-positive analysis, and documentation. See the **AI
Assistance** section of `README.md`.

Claude is deliberately *not* listed as a commit co-author. That is a decision
about placement, not about credit: the acknowledgement belongs once, visibly,
rather than repeated across several thousand commit messages. See CLAUDE.md's
"Git Commit Rules" for the full reasoning.

---

Commit counts are non-merge commits as of 2026-09-03. Contact details are
deliberately omitted here; `git log` has them for anyone who needs them.
