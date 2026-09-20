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

## Clarification (2026-09-20): what a label is, and what it is not

This does not soften the decision above. It says what the public labelled
data is, because an outside review read a TP/FN row as a vulnerability claim.

**A TP, FP or FN row is a statement about the analysis, not about exploitability.**
It is keyed `(project, codebase_commit, file_path, line, rule)`, and it says
only this: at that place, aurora-lint's finding is correct as a statement that
the code departs from the rule as written (TP), is wrong (FP), or the code
departs from the rule and the tool did not flag it (FN). It does not say the
code is a security vulnerability, that input an attacker controls can reach it,
or that anyone has exercised it. Anyone can regenerate the finding data by
running aurora-lint at the pinned tag on the pinned commit; the dataset adds a
verdict, not new information about where to look.

**Calling something a vulnerability takes more evidence, and that evidence is
what this ADR guards.** Before we claim a defect or file an issue upstream we
confirm it with dynamic testing (AddressSanitizer / UBSan / valgrind on a
reproducer) and by reading the path that reaches it. That evidence and its
write-up (reproducers and trigger inputs, sanitizer or valgrind output,
reachability and impact analysis, severity, patches, drafts, timelines) is the
disclosure material governed by the Decision above, and stays out of the
public record until the fix has landed upstream.

**Consequence for the `reason` text of a public row.** A reason records why
the verdict is what it is, in terms of the rule and the shape of the code. It
must not assert that a defect is exploitable or reachable from untrusted input,
quantify an overflow or over-read, name a triggering input (including a sample
query or command), or point at an unpublished reproducer, patch or draft. Once
the fix has landed upstream the reason may say that and cite the upstream
change. A key and verdict alone, for an item that is still unfixed, disclose
nothing a run of the tool would not; a reason that goes further is disclosure
material and belongs in local notes. A reason written earlier that goes further
is rewritten to the label basis; whether the text already in public git history
needs more than that is a separate decision (the 2026-09-16 purge is the
precedent).

**Unchanged:** nothing that locates or describes an unfixed defect beyond its
key and a label-basis reason is published; aggregate statistics about
disclosures are published once the fixes have landed; doing the disclosure work
is expected and is not what this ADR restricts.
