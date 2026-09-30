# 0016. A published artifact cites its sources, ships as a sanitized export, names its accountable reviewer, and discloses AI use

## Status

Proposed (2026-09-30). Brandon to approve the wording; then Accepted.

## Context

This project publishes more than code. It publishes this repository's public
tree and its GitHub Pages site, release archives, the public adjudication
dataset, the papers about aurora-lint, and a book. Three ADRs already govern
parts of that record:

- [ADR-0007](0007-responsible-disclosure-gates-publication.md) governs
  detail about defects in other people's code.
- [ADR-0004](0004-postgres-is-the-single-source-of-truth.md) governs which
  numbers may be published.
- [ADR-0009](0009-changelog-is-for-users-not-a-git-log.md) governs what the
  changelog says.

None of them covers the artifact as a whole: whether its citations are
right, whether it borrows from its sources more than it may, and whether
anything internal rides along with it. Two things showed that gap on
2026-09-30:

- **The citations.** A sweep of the project's bibliographies against the
  primary sources found wrong authors, years, titles and page ranges in
  every one of them. This repository's `docs/bibliography.rst` was one: it
  credited a paper to someone who did not write it. Each error had been
  copied from a secondary source or written from memory.
- **The data.** The measurement snapshots the papers published carried the
  names of internal build machines and task-tracker references. The tool
  that emits them now produces a public-safe document by default, and the
  papers are re-pinned from it.

## Decision

**Before any artifact is submitted or published, it must meet four
conditions.** An artifact is anything that leaves BISSELL: this repository's
public tree and its Pages site, a release archive, a dataset, a paper, or the
book.

1. **It cites its sources correctly and is free of plagiarism.**
   - Verify each citation against the primary source: the work itself
     first, then its DOI registry record. Never write one from memory or
     from a model's output.
   - Learn from sources; do not copy from them. Reproduce no text, figure or
     code from a source whose licence does not allow it. Quote anything
     quoted, and cite it.
   - A file derived from someone else's file keeps that file's licence
     notice. It also records what was changed, who changed it and when, and
     where the unmodified original is. A modified LaTeX bibliography style
     under the LaTeX Project Public License is an example.
2. **It is released only as a sanitized export.**
   - Submit a clean archive of only what the recipient needs to build the
     artifact, to that recipient's standard, together with the final
     output: the PDF, or the release build. Never submit the working
     repository or its build artifacts.
   - The export leaks no personal information and no intellectual property
     beyond what is meant to be published.
   - These never ship: internal machine names and hostnames, IP addresses,
     local filesystem paths, task-tracker ids, and internal URLs. Nor does
     anything ADR-0007 holds back.
   - The exception is authorship that git already makes public: commit
     author names and e-mail addresses. That includes the core maintainer,
     Brandon Arrendondo (brandon.arrendondo@bissell.com).
   - Any other BISSELL Associate is named only with their permission,
     obtained before submission.
3. **It names the accountable BISSELL Associate.** Record, with the artifact,
   the Associate who holds final review responsibility for it. That is
   Brandon Arrendondo unless the artifact says otherwise.
4. **It discloses AI use**, in the form that fits the artifact:
   - the "AI Assistance" section of README.md for the tool;
   - the front matter for the book;
   - a statement in each paper.

   Commit trailers are not the mechanism (see `CLAUDE.md`).

**Also:**

- Every artifact goes through BISSELL legal review before it is submitted
  or published.
- **BISSELL Homecare, Inc. is the primary copyright holder**
  (`docs/licensing.rst`).
- Other holders are credited through the licensing and provenance record
  (`docs/licensing.rst`, `NOTICE`, and the third-party licences it lists),
  or by citation.

These conditions carry out the BISSELL AI Acceptable Use Policy's principles
of accountability, data protection, intellectual property, data quality and
AI attribution.

## Consequences

- **Where the procedure lives.** This ADR is the policy. The step-by-step
  checklist lives with the book, in the book repository's
  `docs/publication-review.md`. That repository is private; the checklist
  links back here. When the procedure changes, change the checklist, not
  this ADR.
- **Nothing is relaxed.** ADR-0007 still governs defect detail, ADR-0004
  which numbers may be published, and ADR-0009 the changelog. This ADR only
  adds conditions.
- **This repository is already a published artifact.** Conditions 1, 2 and 4
  apply to every commit that reaches `origin`, not just to a release. The
  rule against task ids in anything public (`CLAUDE.md`) is one case of
  condition 2.
- **Sanitizing happens at export.** Nothing here justifies stripping working
  material out of the private repositories in advance. Verification notes,
  source comments and working records stay where they are, and the export
  leaves them out. The one exception is working material that prints into
  the artifact itself, such as a verification note in a bibliography field
  the style prints. That is a defect in the artifact, and it is fixed.
- **Re-verification is not per release.** A citation is verified when it is
  added, and again when the artifact that carries it is submitted or
  published.
- **History is a separate decision.** A leak found in text already in public
  git history is fixed at the head. Whether to rewrite history is decided
  case by case, with the 2026-09-16 purge (ADR-0007) as the precedent.
