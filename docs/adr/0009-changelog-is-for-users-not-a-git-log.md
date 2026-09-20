# 0009. The changelog tells users what changed in aurora-lint; it is not a git log or a task list

## Status

Accepted

## Context

`CHANGELOG.md` was generated from the task database: every done task's title
became a public bullet. That produced hundreds of entries per release, most
of them internal work a user of the tool cannot see and does not care about
(benchmark and oracle plumbing, adjudication batches, paper and doc chores,
CI, refactors, task-tracking chatter), and some of them locating unfixed
defects in third-party code, which
[ADR-0007](0007-responsible-disclosure-gates-publication.md) forbids
publishing: a changelog is part of the published record it governs, and it
ships inside every release tarball.
The file was long, unreadable as release notes, and unsafe.

[keepachangelog.com](https://keepachangelog.com) states the principle this
ADR adopts: *don't let your friends dump git logs into changelogs.* A
changelog is a curated, human-written record for the people who *use* the
software, so they can see at a glance what changed between versions. Commit
messages and task titles are working notes for the people who *build* it;
they answer a different question and stay where they are.

## Decision

**`CHANGELOG.md` is written for a user of the aurora-lint tool, and lists
only what that user would notice.** Each release has one dated section
(newest first, with an `[Unreleased]` section on top), and each section has
at most these three headings:

1. **Added** — major feature delivery: a new rule, a new CLI option or
   output format, a new capability of the analyzer. Shipped, user-visible
   things, described by what the user can now do.
2. **Fixed** — bug fixes to the aurora-lint tool: a misfire, a crash, a
   wrong result, a determinism problem. Say what was wrong and what is right
   now, in the user's terms (the construct, the rule id), not the task's.
   A change that alters which findings a scan reports is a user-visible fix
   and belongs here even when it also reduces noise.
3. **Removed** — anything a user could have depended on that is gone:
   a rule, a flag, an output field, a supported platform. Removals are
   listed even when small, because they are the entries that break people.

Everything else does not belong in the changelog, however much work it was:

- benchmark, oracle, adjudication, ground-truth and corpus work (ADR-0004
  keeps those numbers in Postgres; a measurement is not a release note);
- the paper, README/docs-only edits, CI, packaging chores, refactors, tests
  and fixtures added for their own sake, dependency bumps with no user
  effect;
- task ids, task titles, and commit subjects as such.

Entries are written *for publication*: a one- or two-line note authored by a
human or by an agent reading the change, never a task title or commit subject
copied over. Nothing in the changelog may locate a defect in a third-party
codebase or describe a disclosure that has not landed upstream
([ADR-0007](0007-responsible-disclosure-gates-publication.md)), whatever
category it would fall under. `scripts/check_changelog_safety.py` enforces
that in pre-commit, CI and the release workflow, and stays in force: this
ADR narrows what the changelog is *for*; ADR-0007 remains the gate on what it
may *say*.

## Consequences

- The generator is an aid, not the author. `scripts/generate_changelog.py`
  publishes only tasks tagged `release-note`, using the task's
  `release-note:` line. It must be extended so each note carries one of the
  three categories and is emitted under that heading; a note with no
  category is a defect in the note, not something to default into "Added".
- A done task that shipped something a user should hear about gets the tag
  and a written note in the same change. A task that did not ship user-visible
  behavior gets neither, and its absence from the changelog is correct.
- Release sections stay short enough to read. If a release needs pages, the
  entries are too fine-grained or too internal; group them or cut them.
- Historical sections are held to the same standard. Old entries that are
  task titles, internal work, or ADR-0007-class detail are rewritten or
  removed, not preserved as history (the git history is the archive for
  anyone who wants the raw log).
- This ADR does not decide whether public git history or already-published
  release tarballs need scrubbing; that is a separate, outward-facing call
  (see the ADR-0007 follow-up in the task database).
- Keep a Changelog's other headings (Changed, Deprecated, Security) are not
  used. A user-visible behavior change is a Fix or an Addition; a security
  issue follows ADR-0007 and is published only once fixed upstream.
