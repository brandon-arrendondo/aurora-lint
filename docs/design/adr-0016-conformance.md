# ADR-0016 conformance: where the published artifacts fall short

**Status:** swept 2026-10-05 against `1d8778d5` (after the v0.6.0 release),
under the strict reading of ADR-0016. A struck row is fixed, with the
commit beside it. This doc goes stale as fixes land; the rows are the
checklist.

## What this is

A read-only sweep of this repository's published surface against
[ADR-0016](../adr/0016-published-artifacts.md)'s four conditions, plus its
legal-review and copyright clauses. The surface is:

- **The public tree:** README, `docs/`, `docs/design/`, `docs/adr/`, the man
  page (`docs/aurora-lint.1`), source comments and test fixtures, CHANGELOG,
  scripts, tracked data. Every commit that reaches `origin` is published
  (ADR-0016, Consequences).
- **The Pages site:** built from `docs/*.rst` only. `docs/conf.py` loads no
  Markdown parser, so `docs/design/` and `docs/adr/` do not render there;
  they are published through GitHub alone.
- **Release archives:** the binary plus `docs/aurora-lint.1`, README,
  CHANGELOG, LICENSE, NOTICE, `THIRD_PARTY_LICENSES.txt`, the CERT licence
  and the SBOM (`.github/workflows/release.yml`). Nothing else ships, so the
  archives already meet condition 2's "only what the recipient needs".
- **The crates.io package:** `Cargo.toml`'s `include` allowlist, which is
  `src/**`, `tests/**`, `rules_templates/**`, the man page, README, LICENSE,
  NOTICE and the CERT licence. Source comments and fixture headers ship here.

The public label dataset, the papers and the book are out of scope; section
F records what the sweep noticed there.

## Columns

- **Cond**: which ADR-0016 condition (1–4), or L for legal review and
  copyright.
- **Fix**: `done` (struck, commit beside it), `follow-up` (needs more than
  a trivial edit) or `ruling` (the maintainer's call; proposed wording given).

---

## A. Condition 2: internal process, machine names, task ids, paths

| where | what leaks | cond | fix |
|---|---|---|---|
| ~~`bench/runner.py`, `bench/tests/test_generate_changelog.py`, six `docs/design/` docs~~ | "the coordinator" named the maintainers' internal process. `bench/runner.py`'s use meant the parent process that merges shards. **Fixed:** `591cafec`. | 2 | done |
| `.gitignore` lines 36–45, 74–83 | Comments and patterns name the task tracker and its sync. | 2 | ruled acceptable; left |
| ~~`src/analyze/function_summary.rs`, `MEM31-C`, `ARR30-C` comments; `con03-con07-isr-thread-reachability.md`; `realworld-corpus-scope.md`~~ | Task-tracker ids in comments, including a private audit file named by task. **Fixed:** `76955e2e`. | 2 | done |
| ~~`MEM01-C` comment; `exp33-c-cross-file-uninit-architecture.md`, `multi-configuration-scanning.md`, `multiply-defined-names.md`, `internal-capability-catalog.md`, `concurrency-rule-evaluation.md`; an INT30-C fixture header; `scripts/cargo-target-gc.sh`~~ | Bare task numbers and build-machine names. **Fixed:** `ae8948be`. | 2 | done |
| ~~`data/handoff/` (two files)~~ | A build machine's fully qualified home-network hostname on every row; nothing read the files. **Fixed:** `41ce528d` (removed at the head). | 2 | done |
| ~~`bench/db.py` docstring; `Cargo.toml` comment~~ | A real home directory; a private repository's name. **Fixed:** `9814d5aa`. | 2 | done |
| `docs/design/` as a whole | Many design docs are written as task notes: "the task's framing", "filed as its own task", "this pass", and more bare task numbers than a pattern search finds reliably (three-digit ids look like counts). The commits above fixed the ones a search found unambiguously. | 2 | follow-up: one read-through pass of `docs/design/`, or settle the expected relaxation for `docs/` first |
| `docs/design/gate-status-sop.md` | The whole doc is a maintainer procedure over the task database: task ids, tracker commands, raw queries against its db file. | 2 | follow-up: move out of the public tree (`CLAUDE.md` points at it and would change with it) |
| `data/competitor_results/run_hosts.json`, `competitor_runs.csv`; `bench/competitor_csv.py` docstring | Build-machine names are the host-attribution data itself (`hostname` column, keyed host descriptions). | 2 | follow-up: replace with neutral host labels (e.g. "host A, ~2012 Xeon") in the data and the reader together |
| `bin/mcp-sqc-benchmark-query.sh`, `bin/mcp-sqc-benchmark-queue.sh` | Hard-coded local paths into a sibling checkout; maintainer-workflow machinery that `CLAUDE.md` says belongs outside this repo. Nothing tracked references them. | 2 | follow-up: remove, or move to the benchmark-data repo |
| `scripts/cargo-target-gc.sh` default repo list; `playbooks/setup-dev-environment.yml` and `docs/contributing.rst` `dev_venv` example | The maintainers' own directory layout as defaults and examples. | 2 | follow-up (low): placeholders, or require the list as arguments |
| `scripts/generate_changelog.py` usage example; `bench/tests/test_generate_changelog.py` "fleet task schema" | Names the task database's file and calls the tracker by an internal name. | 2 | follow-up (low) |
| `src/` comments pointing at `data/precision_audit/...` (EXP20-C, EXP36-C, MSC12-C ×4) | Pointers to private working data no reader can open. Not a leak in itself, but they ship in the crate and point at nothing. | 2 | follow-up (low): state the finding inline, drop the path |
| `.claude/commands/*.md`, `.claude/lock-list.yaml` | An agent workflow for a proposals directory that is not in the tree. | 2 | follow-up (low): confirm still wanted in the public tree |
| `CLAUDE.md` | Describes worker nodes, the shared Postgres instance by name, the benchmark-data repos and maintainer workflow. It is the agent instruction file, so some of this is its purpose. | 2 | ruling: what a public `CLAUDE.md` may say |
| README, `docs/reproducing-published-numbers.rst`, `docs/testing-methodology.rst`, `docs/design/macro-expansion.md`: "run #265" and similar | Benchmark run ids. These are measurement provenance (run 265's keys are under `tests/golden/run-265/`), not task-tracker ids. | 2 | no change proposed |
| `docs/design/finding-location.md` batch names (`task-644-full-reaudit`, …) | Batch directory names in the public label dataset, which may be cited as dataset identifiers. | 2 | no change proposed (renaming belongs to the dataset) |

## B. Condition 2: ADR text (proposed wording only)

The accepted ADRs credit a build machine by name. The edits are cosmetic,
but they change accepted ADR text, so they are proposed rather than made.

| where | today | proposed |
|---|---|---|
| ADR-0005, Consequences | "came out of dev-180's own catch, the same day ADR-0002 was written — worth stating explicitly rather than learned per-agent per-session." | "came out of a review the same day ADR-0002 was written — worth stating explicitly rather than relearned case by case." |
| ADR-0006, Consequences | "Credit: pattern identified by dev-180 across EXP05-C, INT02-C, and INT16-C …" | "Credit: pattern identified in review across EXP05-C, INT02-C, and INT16-C …" |
| ADR-0008, Consequences | "Credit: measured by dev-180 under that audit, …" | "Credit: measured under that audit, …" |

## C. Condition 1: citations, plagiarism, derived files

Every literature citation outside `docs/bibliography.rst` (re-verified
earlier, out of scope here) was checked against the work itself and then its
DOI registry or arXiv record. Literature is cited only in
`docs/architecture.rst`, `docs/juliet-history.rst`,
`docs/future-rulesets.rst`, `docs/testing-methodology.rst`, ADR-0010,
ADR-0015, `docs/design/finding-location.md` (FL) and
`docs/design/adr-external-alignment.md` (AEA); the man page, README and the
other docs cite none. Keys into `bibliography.rst` (Lipp2022, Goseva2015,
Christakis2016) resolve, and the claims made about them hold. Only the
departures are listed. None was fixed on this branch: each changes a claim,
so each needs its own re-check at the source before the edit.

| where | departure | cond | fix |
|---|---|---|---|
| `docs/juliet-history.rst` ~1315 | "Commercial Tool C ~73% detection" is its G-score; Goseva-Popstojanova & Perhinschi 2015, Table 3, give overall recall 59% (mean per-CWE 39%), false-alarm 7%. | 1 | follow-up |
| `docs/juliet-history.rst` ~1266–1279 | Semgrep CE/Pro figures were measured on WebGoat (Java) and Juice Shop (Node), not C or Juliet, yet sit in a Juliet C table. | 1 | follow-up |
| `docs/juliet-history.rst` ~1280–1300 | Infer, Flawfinder and CodeQL figures: no listed source contains them. | 1 | follow-up: cite or remove |
| `docs/juliet-history.rst` ~1308 | Coverity "~15–20% FP" is Bessey et al.'s target ("below 20%"), not a measured rate. | 1 | follow-up |
| `docs/juliet-history.rst` ~1352 | "JKU 2014" lacks authors and title (Wagner & Sametinger, 2014). | 1 | follow-up |
| `docs/future-rulesets.rst` ~46, ~54 | Power of Ten rule 1 omits setjmp/longjmp and indirect recursion; rule 9 allows one level of dereferencing, not two (two is D-60411's). Check what the implemented rule enforces. | 1 | follow-up |
| `docs/future-rulesets.rst` ~44 | "They complement MISRA C guidelines" is not in Holzmann's paper (the link is D-60411's). | 1 | follow-up |
| `docs/future-rulesets.rst` ~48, 51, 79–93, 111 | Rule text from Power of Ten, D-60411 and Barr Group's own description copied near-verbatim without quotation marks. | 1 | follow-up: quote and cite, or rephrase |
| `docs/testing-methodology.rst` ~519 | "SEI SCALe 2015 report" lacks author and title (Svoboda, *SCALe Analysis of JasPer Codebase*, SEI, 2015). | 1 | follow-up |
| ADR-0010 ~110, ADR-0015 ~213 | "JPL D-60411, Rules 15–16" for explicit recovery: only Rule 16 says it; Rule 15 is parameter validity. | 1 | ruling (ADR text): "Rule 16" |
| FL ~209–215 | SATE IV sections: §2.6, §2.7.1 and §2.9.7, not "§2.6 and §2.9.6". | 1 | follow-up |
| FL ~222–226 | Hovemeyer & Pugh: the non-null-parameter point is §3.6. | 1 | follow-up |
| FL ~227–231 | Engler et al. §7.2 is hypothetical ("would cause"), blames type coercion, and concerns a user-pointer checker; "direct evidence" overstates it. | 1 | follow-up |
| FL ~173 | The Juliet User Guide is v1.2 (there is no 1.3 guide). | 1 | follow-up |
| FL ~332 | Tricorder makes no prediction about developers; only Bessey supports the sentence. | 1 | follow-up |
| AEA ~168–170 | Zobel 1998 and Buckley et al. 2007 do not show pools favour contributing systems. | 1 | follow-up |
| AEA ~358 | The "did not want to see" phrase is Tricorder quoting Ayewah et al.; Tricorder's own definition differs. | 1 | follow-up |
| AEA ~491 | "Effective-FP rates of tens of percent are normal" is contradicted by Tricorder (<10%) and Christakis & Bird. | 1 | follow-up |
| AEA ~383 | SATE's example is a construct confusion (call taken for a variable), not a spelling confusion. | 1 | follow-up |
| AEA ~393 | Ockham §2.3 uses CERT's sense of "sound", not the PL sense. | 1 | follow-up |
| AEA ~779 | The Bodik "9 to 40%" figure is the FSE'97 paper quoting their PLDI'97 measurement. | 1 | follow-up |
| AEA ~947 | LLM4FPM's 86% on D2A is label accuracy, not F1. | 1 | follow-up |
| AEA ~417 | Padioleau's ~96% has no reference, and is a parse-success rate, not an error rate. | 1 | follow-up |
| AEA reference list (~1133–1161) | Many entries are bare URLs or partial (no authors, title, venue or DOI); Soundiness lacks its venue; Bodik's venue is ESEC/FSE '97; Tartler can now be marked checked. | 1 | follow-up |

| where | what | cond | fix |
|---|---|---|---|
| Wiki-derived test fixtures (`src/rules/cert_c/*/*/tests/**`, those with a `Source: wiki` header) | Each declares its provenance, and `NOTICE`, `thirdparty/cert/LICENSE` and `docs/licensing.rst` record the licence centrally. No fixture carries the licence notice itself, what was changed, or which wiki page holds the unmodified original, which the strict reading of condition 1's third bullet asks of each derived file. These ship in the crate. | 1 | ruling: whether the central record suffices; if not, a mechanical header pass (`scripts/fixture_provenance.py` already finds the set) |
| Rule manifests (`src/rules/cert_c/*/*/*-C.toml`) | `metadata.title`/`description` lifted from the CERT standard and reflowed; licence recorded centrally, and most cite their wiki page. Same question as the fixtures. | 1 | ruling (same as above) |

## D. Condition 3: the accountable Associate

No artifact in this repository records who holds final review
responsibility. ADR-0016 defaults it to Brandon Arrendondo but asks that it
be recorded with the artifact. Proposed lines, one per artifact:

| artifact | where | proposed line |
|---|---|---|
| the tool (repo, crate, release archives) | README, a short paragraph under "License" (README ships in all three) | "Final review responsibility for this repository, its releases and its documentation rests with Brandon Arrendondo, BISSELL Homecare, Inc." |
| the man page | `docs/aurora-lint.1`, `.SH AUTHORS`, after the author list | "Final review: Brandon Arrendondo." |
| the Pages site | `docs/index.rst`, a closing line, or `docs/licensing.rst` | same sentence as README |
| the public label dataset | its README (out of scope here) | "Final review responsibility for this dataset rests with Brandon Arrendondo, BISSELL Homecare, Inc." |
| each paper | front matter / author note (out of scope here) | "Brandon Arrendondo (BISSELL Homecare, Inc.) holds final review responsibility for this paper." |
| the book | copyright page (out of scope here) | same form as the papers |

## E. Condition 4 and legal review

| where | what | cond | fix |
|---|---|---|---|
| README "AI Assistance" | Present, and README ships in the crate and every release archive. | 4 | none |
| Pages site, man page | Neither carries an AI-use line. ADR-0016 names README as the tool's mechanism, so this is not a departure; a one-line pointer in `docs/index.rst` would make the site self-contained. | 4 | follow-up (optional) |
| Copyright | `NOTICE`, `docs/licensing.rst`, `docs/conf.py`, the man page and README all name BISSELL Homecare, Inc.; third-party terms are recorded in `NOTICE`, `thirdparty/cert/LICENSE` and `THIRD_PARTY_LICENSES.txt`. Every person named (`Cargo.toml` authors, the man page, `CONTRIBUTORS.md`) is a git commit author, which condition 2 already makes public. | L | none |
| Legal review | Nothing in the tree records that an artifact went through legal review before publication, and ADR-0016 does not say where that is recorded. | L | ruling: whether the pre-publication checklist (kept outside this repo) is the record |

## F. Outside this repo (noted, not edited)

- **Public label dataset:** raw adjudicator ids that name build machines,
  and an internal tag on some `ground_truth` rows. Ruled low priority and
  tracked separately.
- **The book:** printed "verified https://api.crossref.org/..." notes in
  bibliography fields the style prints are, under ADR-0016's Consequences,
  a defect in the artifact.
- **Papers and book:** each carries an AI-use statement; the accountable
  Associate line (section D) is not yet recorded in any of them.
