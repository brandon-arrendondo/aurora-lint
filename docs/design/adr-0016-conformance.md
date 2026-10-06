# ADR-0016 conformance: where the published artifacts fall short

**Status:** swept 2026-10-05 against `1d8778d5` (after the v0.6.0 release),
under the strict reading of ADR-0016, with the maintainer's rulings of the same
day applied. A struck row is fixed or closed, with the
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
- **Fix**: `done` (struck, commit beside it), `closed` (struck, ruled not a
  departure), `follow-up` (needs more than a trivial edit) or `ruling`.

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
| ~~`docs/design/gate-status-sop.md`~~ | The whole doc was a maintainer procedure over the task database: task ids, tracker commands, raw queries against its db file. **Fixed:** `8712358b` (removed). `CLAUDE.md`'s pointer to it was removed too. | 2 | done |
| ~~`data/competitor_results/run_hosts.json`, `competitor_runs.csv`; `bench/competitor_csv.py` docstring~~ | Build-machine names were the host-attribution data itself. **Fixed:** `fd563910`; the hosts are now host-a and host-b, and the CSV was regenerated. | 2 | done |
| ~~`bin/mcp-sqc-benchmark-query.sh`, `bin/mcp-sqc-benchmark-queue.sh`~~ | Hard-coded local paths into a sibling checkout; maintainer-workflow machinery. Nothing tracked referenced them. **Fixed:** `9e46a69b` (removed). | 2 | done |
| ~~`scripts/cargo-target-gc.sh` default repo list; `playbooks/setup-dev-environment.yml` and `docs/contributing.rst` `dev_venv` example~~ | The maintainers' own directory layout as defaults and examples. **Fixed:** `6e15d54b`; the script defaults to the clone under `$AURORA_LINT_SRC_ROOT`, and the playbook passes its `gc_repos` list. | 2 | done |
| ~~`scripts/generate_changelog.py` usage example; `bench/tests/test_generate_changelog.py` "fleet task schema"~~ | Named the task database's file and called the tracker by an internal name. **Fixed:** `9d6f8d6a`. | 2 | done |
| ~~`src/` comments pointing at `data/precision_audit/...` (EXP20-C, EXP36-C, MSC12-C ×4)~~ | Pointers to private working data no reader can open. **Fixed:** `a061d5ef`; each states which adjudication found it. | 2 | done |
| ~~`.claude/commands/*.md`, `.claude/lock-list.yaml`~~ | An agent workflow whose proposals directory and helper scripts are gone from the tree. **Fixed:** `4b8f71b8` (removed). | 2 | done |
| `CLAUDE.md` | A public `CLAUDE.md` should hold only instructions relevant to anyone cloning the repo, with pointers to the ADRs (maintainer's ruling). Maintainer workflow that should move out: "Where benchmark data lives" (the shared Postgres instance, the benchmark-data and dataset repos, worker nodes; keep the local-run paragraph); "Protocol" steps on pushing for the shared queue, the multi-node version-bump rationale, and delta-adjudication against the shared oracle (keep commit-before-benchmarking, don't-rebuild-mid-run and the `sqc` identifier note); "Querying results" except its first paragraph; "Refreshing published doc numbers" on publishing from Postgres; "Task tracking" (keep only the rule against task ids in public text, pointing at ADR-0016); the paper and gate-status rows of "Documentation"; the per-machine memory guidance in "Maintaining this file". | 2 | follow-up: restructure as its own change |
| README, `docs/reproducing-published-numbers.rst`, `docs/testing-methodology.rst`, `docs/design/macro-expansion.md`: "run #265" and similar | Benchmark run ids. These are measurement provenance (run 265's keys are under `tests/golden/run-265/`), not task-tracker ids. | 2 | no change proposed |
| `docs/design/finding-location.md` batch names (`task-644-full-reaudit`, …) | Batch directory names in the public label dataset, which may be cited as dataset identifiers. | 2 | no change proposed (renaming belongs to the dataset) |

## B. Condition 2: ADR text

| where | what leaked | cond | fix |
|---|---|---|---|
| ~~ADR-0005, ADR-0006, ADR-0008, Consequences~~ | Each credit named an internal build machine. **Fixed:** `dccd2f21`; the credits now say the finding came from development or testing. | 2 | done |

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
departures are listed. Each fix changed a claim, so each was re-checked at
the source before its edit and landed as its own commit.

| where | departure | cond | fix |
|---|---|---|---|
| ~~`docs/juliet-history.rst` ~1315~~ | "Commercial Tool C ~73% detection" is its G-score; Goseva-Popstojanova & Perhinschi 2015, Table 3, give overall recall 59% (mean per-CWE 39%), false-alarm 7%. **Fixed:** `639ef449`. | 1 | done |
| ~~`docs/juliet-history.rst` ~1266–1279~~ | Semgrep CE/Pro figures were measured on WebGoat (Java) and Juice Shop (Node), not C or Juliet, yet sit in a Juliet C table. **Fixed:** `de2f747f`. | 1 | done |
| ~~`docs/juliet-history.rst` ~1280–1300~~ | Infer, Flawfinder and CodeQL figures: no listed source contains them. **Fixed:** `991bcf03` (rows removed). | 1 | done |
| ~~`docs/juliet-history.rst` ~1308~~ | Coverity "~15–20% FP" is Bessey et al.'s target ("below 20%"), not a measured rate. **Fixed:** `060df6bd`. | 1 | done |
| ~~`docs/juliet-history.rst` ~1352~~ | "JKU 2014" lacks authors and title (Wagner & Sametinger, 2014). **Fixed:** `b3f07602`. | 1 | done |
| ~~`docs/future-rulesets.rst` ~46, ~54~~ | Power of Ten rule 1 omits setjmp/longjmp and indirect recursion; rule 9 allows one level of dereferencing, not two (two is D-60411's). Check what the implemented rule enforces. **Fixed:** `85d41d53` (rule 1), `4f0d1ca3` (rule 9; BRULE-065 enforces D-60411 Rule 26's two levels per declaration, and the docs now say so). | 1 | done |
| ~~`docs/future-rulesets.rst` ~44~~ | "They complement MISRA C guidelines" is not in Holzmann's paper (the link is D-60411's). **Fixed:** `507c4113`. | 1 | done |
| ~~`docs/future-rulesets.rst` ~48, 51, 79–93, 111~~ | Rule text from Power of Ten, D-60411 and Barr Group's own description copied near-verbatim without quotation marks. **Fixed:** `acf8c4e9` (P10 and D-60411 paraphrased with rule numbers; Barr Group quoted). | 1 | done |
| ~~`docs/testing-methodology.rst` ~519~~ | "SEI SCALe 2015 report" lacks author and title (Svoboda, *SCALe Analysis of JasPer Codebase*, SEI, 2015). **Fixed:** `7b3e7adc` ("only" softened to the only one we found). | 1 | done |
| ~~ADR-0010 ~110, ADR-0015 ~213~~ | "JPL D-60411, Rules 15–16" for explicit recovery: only Rule 16 says it; Rule 15 is parameter validity. **Fixed:** `cc6fff6d`. | 1 | done |
| ~~FL ~209–215~~ | SATE IV sections: §2.6, §2.7.1 and §2.9.7, not "§2.6 and §2.9.6". **Fixed:** `013c7b6c`. | 1 | done |
| ~~FL ~222–226~~ | Hovemeyer & Pugh: the non-null-parameter point is §3.6. **Fixed:** `777ac85a`. | 1 | done |
| ~~FL ~227–231~~ | Engler et al. §7.2 is hypothetical ("would cause"), blames type coercion, and concerns a user-pointer checker; "direct evidence" overstates it. **Fixed:** `45d7bf75`. | 1 | done |
| ~~FL ~173~~ | The Juliet User Guide is v1.2 (there is no 1.3 guide). **Fixed:** `a659c8fc`. | 1 | done |
| ~~FL ~332~~ | Tricorder makes no prediction about developers; only Bessey supports the sentence. **Fixed:** `a3d63251`. | 1 | done |
| ~~AEA ~168–170~~ | Zobel 1998 and Buckley et al. 2007 do not show pools favour contributing systems. **Fixed:** `6e819d40`. | 1 | done |
| ~~AEA ~358~~ | The "did not want to see" phrase is Tricorder quoting Ayewah et al.; Tricorder's own definition differs. **Fixed:** `90a0b2a1`. | 1 | done |
| ~~AEA ~491~~ | "Effective-FP rates of tens of percent are normal" is contradicted by Tricorder (<10%) and Christakis & Bird. **Fixed:** `5f27736d`. | 1 | done |
| ~~AEA ~383~~ | SATE's example is a construct confusion (call taken for a variable), not a spelling confusion. **Fixed:** `27af5e76`. | 1 | done |
| ~~AEA ~393~~ | Ockham §2.3 uses CERT's sense of "sound", not the PL sense. **Fixed:** `10e2af3d`. | 1 | done |
| ~~AEA ~779~~ | The Bodik "9 to 40%" figure is the FSE'97 paper quoting their PLDI'97 measurement. **Fixed:** `e27ea46c`. | 1 | done |
| ~~AEA ~947~~ | LLM4FPM's 86% on D2A is label accuracy, not F1. **Fixed:** `1a0a0001`. | 1 | done |
| ~~AEA ~417~~ | Padioleau's ~96% has no reference, and is a parse-success rate, not an error rate. **Fixed:** `022295eb` (reference added; the figure stays flagged unverified, full text unreachable). | 1 | done |
| ~~AEA reference list (~1133–1161)~~ | Many entries are bare URLs or partial (no authors, title, venue or DOI); Soundiness lacks its venue; Bodik's venue is ESEC/FSE '97; Tartler can now be marked checked. **Fixed:** `da3fd5c2`. | 1 | done |
| AEA ~996, ~515 | Lipp et al. §5.1 (the four-scenario reading of the 47–80% range; the abstract, which was read, gives the range) and the ACM badging page could not be reached in this pass (bot wall, paywall, 403). The ACM claim already carries an "unverified" note; the Lipp §5.1 reading is recorded as checked in an earlier pass and matches `docs/bibliography.rst`. No text changed. | 1 | open: re-check when reachable |
| ~~`docs/future-rulesets.rst` BARR-C "Key embedded-specific areas"~~ | The four bullets (volatile, file naming, comments, braces) are not on Barr Group's page that the rest of the paragraph quotes, and the standard's own text was not available to check them. **Fixed:** removed; the section now cites only Barr Group's public page. | 1 | done |

| where | what | cond | fix |
|---|---|---|---|
| ~~Wiki-derived test fixtures (`src/rules/cert_c/*/*/tests/**`, those with a `Source: wiki` header)~~ | Each declares its provenance; `NOTICE`, `thirdparty/cert/LICENSE` and `docs/licensing.rst` record the licence centrally, and no fixture carries a per-file notice, change record or link to its original. **Closed:** the CERT code examples are under a permissive licence, so the central record suffices (maintainer's ruling). | 1 | closed |
| ~~Rule manifests (`src/rules/cert_c/*/*/*-C.toml`)~~ | `metadata.title`/`description` lifted from the CERT standard and reflowed; licence recorded centrally. **Closed** on the same ruling. | 1 | closed |

## D. Condition 3: the accountable Associate

ADR-0016 asks that each artifact record the Associate who holds final
review responsibility. For this repository's artifacts the line is:
"Brandon Arrendondo is the accountable BISSELL Associate for aurora-lint:
he maintains it and writes its documentation."

| artifact | where | fix |
|---|---|---|
| ~~the tool (repo, crate, release archives)~~ | README, under "License" (README ships in all three). **Fixed:** `45cdbfae`. | done |
| ~~the man page~~ | `docs/aurora-lint.1`, `.SH AUTHORS`, after the author list. **Fixed:** `45cdbfae`. | done |
| ~~the Pages site~~ | `docs/index.rst`, the opening page. **Fixed:** `45cdbfae`. | done |
| the public label dataset | its README (another repository) | follow-up there: same name; Brandon Arrendondo maintains the dataset and its README |
| knots | its README (another repository) | follow-up there: same name; he maintains it |
| each paper | front matter or author note (other repositories) | follow-up there: same name, as the responsible Associate for the paper |
| the book | copyright page (outside this repository) | follow-up there: same name, as the responsible Associate for the book |

## E. Condition 4 and legal review

| where | what | cond | fix |
|---|---|---|---|
| README "AI Assistance" | Present, and README ships in the crate and every release archive. | 4 | none |
| Pages site, man page | Neither carries an AI-use line. ADR-0016 names README as the tool's mechanism, so this is not a departure; a one-line pointer in `docs/index.rst` would make the site self-contained. | 4 | follow-up (optional) |
| Copyright | `NOTICE`, `docs/licensing.rst`, `docs/conf.py`, the man page and README all name BISSELL Homecare, Inc.; third-party terms are recorded in `NOTICE`, `thirdparty/cert/LICENSE` and `THIRD_PARTY_LICENSES.txt`. Every person named (`Cargo.toml` authors, the man page, `CONTRIBUTORS.md`) is a git commit author, which condition 2 already makes public. | L | none |
| Legal review | Recorded, when available, under `docs/legal/` (maintainer's ruling). No review is recorded there yet, and the directory does not exist until one is. | L | pending a review to record |

## F. Outside this repo (noted, not edited)

- **Public label dataset:** raw adjudicator ids that name build machines,
  and an internal tag on some `ground_truth` rows. Ruled low priority and
  tracked separately.
- **The book:** printed "verified https://api.crossref.org/..." notes in
  bibliography fields the style prints are, under ADR-0016's Consequences,
  a defect in the artifact.
- **Papers and book:** each carries an AI-use statement; the accountable
  Associate line (section D) is not yet recorded in any of them.
