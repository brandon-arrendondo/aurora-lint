# 0007. A disclosure becomes part of the published record only once it has landed upstream

## Status

Accepted

## Context

Part of aurora-lint's real-world evaluation is running it against shipping
open-source codebases (SQLite, hostap, raylib, mosquitto, mbedtls, curl,
etc.) and adjudicating the findings. Some of those findings are real defects,
reported to the upstream maintainers as security or correctness disclosures.
Citing the fixed ones is a genuine, valuable proof point — it's evidence
aurora-lint catches real bugs in real shipping software, not just synthetic
Juliet cases, and it belongs in README as a highlight.

But the same adjudication process produces detail on defects that are
*not yet fixed*: drafts not yet sent, disclosures filed but unacknowledged,
findings deliberately held back pending a maintainer's fix. Publishing
project/file/line/mechanism detail on those is irresponsible disclosure — it
hands anyone reading this repo a roadmap to an unpatched vulnerability in
software other people are running.

This distinction wasn't enforced by anything except habit. `data/precision_audit/`
(adjudication findings against real codebases) and `docs/upstream-disclosures.rst`
(defect-by-defect disclosure detail, mixing already-fixed and still-in-flight
items) were both committed to git, and `docs/upstream-disclosures.rst` was
built and deployed to this project's public GitHub Pages site — live, not
just sitting in history. Both were purged from git history and local-only
storage on 2026-09-16 (see `CLAUDE.md`'s Benchmark Workflow section for
where `data/precision_audit`-equivalent working data lives now). This ADR is
the standing rule so the same thing doesn't happen again the next time
someone adds a disclosure.

## Decision

**A disclosure's detail — project, file, mechanism, timeline, or anything
specific enough to locate the defect — enters this repo's published record
(README, `docs/upstream-disclosures.rst` or equivalent, a commit message, a
gh-pages-deployed doc, the paper) only after the fix has actually landed
upstream** — merged or released in the upstream project, not merely
"reported," "acknowledged," or "fix drafted."

Until it lands:

- Working detail (drafts, adjudication notes, correspondence, timelines)
  stays in storage that never reaches `origin` — local files, a private
  store, whatever this session's working-data convention is (see
  `CLAUDE.md`) — never a git commit in this repo, and never anything that
  gets built into a Sphinx page deployed to gh-pages.
- Filing the disclosure with the maintainer, tracking it as pending, and
  doing the adjudication work that produced it are all fine and expected.
  The gate is specifically on what becomes part of this project's public,
  citable record — not on doing the disclosure work itself.

Once a fix lands, both defect-by-defect detail and aggregate stats
("N disclosed, N fixed, median time-to-fix") are fair game and should be
published — that evidence is one of the project's real highlights, not
something to undersell out of excess caution.

## Consequences

- `data/precision_audit/` and `docs/upstream-disclosures.rst` are gitignored
  as of 2026-09-16; disclosure-adjudication work happens in local,
  non-git-tracked storage until promotion.
- The adjudicated TP/FP/FN labels this work produces have a durable public
  home once ready: `benchmark_adjudication`, a separate PR-gated repo with
  its own reviewer checklist for exactly this ADR's concern (a free-text
  `reason`/`provenance` field naming an unlanded defect). That repo, not
  this one, is where labeled ground_truth becomes a shareable dataset —
  see its README for the review process.
- Before adding disclosure detail to README, `docs/upstream-disclosures.rst`,
  a commit message, or anything that reaches gh-pages: confirm the specific
  fix has landed upstream, not just that a report was sent.
- README's existing aggregate claims about already-fixed disclosures (e.g.
  "N of N confirmed and fixed upstream") are the sanctioned shape and don't
  need to be pulled — they describe landed fixes, which is exactly what this
  ADR clears for publication.
- Doesn't relitigate whether aurora-lint should do upstream disclosure at
  all — it should, and continuing to do so is expected. This governs only
  when the record of it becomes public.
