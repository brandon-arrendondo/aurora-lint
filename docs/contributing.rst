Contributing
============

Adding a New CERT C Rule
------------------------

The full checklist, and the policy a new rule must follow, are in the
"Build & Test" and "Rule Implementation" sections of
the `technical guide <https://github.com/brandon-arrendondo/aurora-lint/blob/main/CLAUDE.md>`_.
In short:

1. Create ``src/rules/cert_c/CATEGORY/RULE-ID/`` with the implementation
   (``rule_id_c.rs``) and the rule's ``RULE-ID.toml``. Copy a small existing
   rule as the template: ``src/rules/cert_c/MSC/MSC33-C/`` implements the
   ``CertRule`` trait (``src/rules/mod.rs``) in one short file. The build
   merges each ``RULE-ID.toml`` into ``rules_templates/rules-all.toml``, so
   do not edit that file by hand.

2. Register the rule in ``src/rules/cert_c/mod.rs``.

3. Add test cases as ``.c`` files in ``tests/fail/`` and ``tests/pass/``
   (and ``tests/expected_fail/`` for a known miss) beside the rule. The
   build generates a test from each file; do not add inline tests.

4. Add a block for the rule to every ``conf/realworld/*-rules.toml``. The
   ``check-realworld-manifests`` hook refuses a commit without one.

5. Build and run the rule's tests. The filter is the rule id in lower case,
   with ``_`` for ``-`` (here for MSC33-C):

   ::

       cargo build
       cargo test --lib -- msc33_c
       cargo fmt

Removing a Rule
---------------

A rule is removed only on its row in ``docs/design/rule-disposition.md``
(ADR-0013): a not-shipped disposition, ruled. Each removal is its own change
(Decision 5), and "not shipped" means gone from the tool, not disabled
(Decision 4). In that one change:

1. Check that the covering rule already reports the construct (Decision 5):
   run it on the removed rule's ``fail`` fixtures and CERT's noncompliant
   examples. If it doesn't, the removal waits for that coverage to land.

2. Delete the rule directory ``src/rules/cert_c/CATEGORY/RULE-ID/`` (the
   implementation, its ``.toml`` and its ``tests/`` fixtures) and its
   registration in ``src/rules/cert_c/mod.rs``.

3. Delete its block from every ``conf/realworld/*-rules.toml``. The build
   regenerates ``rules_templates/rules-all.toml`` without it.

4. Add a ``[[removed]]`` entry to ``rules_templates/removed-rules.toml``, in
   id order (the loader refuses an unsorted table, so parallel removals don't
   all conflict at the end of the file). ``removed_in`` is the release the
   removal ships in, set up front; ``disposition``, ``covered_by`` and (for
   a check moved to the CWE ruleset) ``moved_to`` must agree with the rule's
   disposition row, and every ``covered_by`` rule must still ship (a test
   checks it against the registry).

5. Regenerate what is derived from the rule set:

   ::

       python3 scripts/generate_rule_cwe_map.py   # data/rule_cwe_map.json
       python3 scripts/render_removed_rules.py    # README.md and docs/configuration.rst

   Delete the rule's key from ``data/wiki_fixture_staleness.json`` (its
   fixtures are gone; don't rerun that audit, which fetches CERT's wiki),
   and fix every rule count the ``check-project-facts`` hook reports as
   stale (README.md and docs/ claim the shipped and enabled totals).

6. Record the removal in the rule's row in
   ``docs/design/rule-disposition.md``: note it, with the release, in the
   *Reason / notes* column. Leave the *Disposition* column as the
   not-shipped disposition the removal rests on; the ``check-removed-rules``
   hook requires it to start with that label (and to name every
   ``covered_by`` rule, and the ``moved_to`` CWE). Also update any design doc or ADR that
   cites the rule as live (for example ``docs/design/cross-rule-overlap.md``).

7. Say in the change's description what users lose and which rules report
   the construct instead. The maintainer records it as the release note,
   under ``category: removed`` (ADR-0009).

8. Build and run the full test suite. The pre-commit hooks check that every
   real-world manifest still decides every rule (``check-realworld-manifests``),
   that the not-shipped list is current and agrees with the disposition
   table (``check-removed-rules``), and that the rule counts hold
   (``check-project-facts``).

Moving a Check to the CWE Ruleset
---------------------------------

A rule whose disposition is *moved to CWE ruleset* keeps its check and
changes its id: it is shipped from ``src/rules/cwe/`` as ``CWE-<n>``, enabled
by default as before, and the CERT id is recorded as removed. The removal
steps above apply, with these differences:

1. There is no covering rule to check: the moved rule reports the construct
   itself.

2. Move the rule directory with ``git mv`` to ``src/rules/cwe/CWE-<n>/``
   (flat: no category level), renaming the ``.rs`` file and the ``.toml`` to
   match, rather than deleting it. Change the rule id, the struct name and
   the ``[rules.cert_c.<ID>]`` table to ``[rules.cwe.CWE-<n>]``, set the
   ``[metadata]`` ``type`` to ``weakness``, and change each fixture's
   ``Rule:`` header. Move the registration from ``src/rules/cert_c/mod.rs``
   to ``src/rules/cwe/mod.rs`` and the ``register`` call beside the other
   CWE rules. Keep ``[references] cwe`` as it was: it names the Juliet
   directories the check is scored on, which the move does not change.

3. In every ``conf/realworld/*-rules.toml``, move the rule's block to the CWE
   ruleset section at the end of the file as ``[rules.cwe.CWE-<n>]``,
   keeping that codebase's decision and its comment. Coverage on the
   real-world suite must not change. ``rules_templates/rules-all.toml`` is
   regenerated by the build.

4. The ``[[removed]]`` entry takes ``disposition = "moved-to-cwe"`` and
   ``moved_to = "CWE-<n>"``, which must be a rule the tool ships, and no
   ``covered_by``.

5. A suppression comment or ``--rules`` naming the old id still parses, with
   a warning, but no longer matches. The release note says so: it is a
   ``removed`` note for the CERT id and an ``added`` note for the CWE id.

6. Ground-truth labels are keyed on the rule id, so the old id's labels
   stop matching anything. Count them per id and re-key them through
   ``benchmark_adjudication`` (ADR-0007), rather than letting them drop out
   of the oracle silently.

7. Check with a before/after scan of the real-world corpora: the findings
   must be the same in everything except the rule id.

Build Requirements
------------------

- **Rust**: 1.95 or later (stable toolchain; ``rust-version`` in Cargo.toml)
- **C toolchain**: a C compiler and linker for dependencies with native code
  (e.g. ``libgit2-sys``); ``build-essential`` on Debian/Ubuntu
- **Platform**: Linux, macOS, Windows (cross-platform via crossterm)
- **Dependencies**: See ``Cargo.toml`` for the full list

::

    cargo build             # Debug build
    cargo build --release   # Release build (optimized)
    cargo test              # Run all tests
    cargo fmt               # Format code

Invoke Tasks
------------

``tasks.py`` holds a few developer tasks, run with
`invoke <https://www.pyinvoke.org/>`_ (``pip install invoke``):

::

    invoke check            # Run pre-commit hooks on all files
    invoke build            # Build (add --release for release mode)
    invoke test             # Run all tests
    invoke bump-version     # Bump version across all files (reads Cargo.toml)
    invoke lint-docs        # Advisory prose lint of README.md, docs/*.rst, man page

``invoke lint-docs`` runs `Vale <https://vale.sh>`_ with the Aurora house
style (American spelling, settled terms such as "pre-scan", no contractions,
and a flag on patterns typical of machine-written prose). The style is a
Vale package in a sibling ``../style_package`` checkout, named in
``.vale.ini``; the task builds its zip there when missing and reruns
``vale sync`` when ``.vale.ini`` or the zip changes. A checkout without
``../style_package`` cannot run it, and nothing else depends on it.

By default it lints the user-facing docs: ``README.md``, this guide
(``docs/*.rst``) and the man page, which pandoc first converts to Markdown
under ``target/vale/`` (findings name that file). Pass ``--path`` for any
other tracked ``.md`` or ``.rst`` file or directory, such as the internal
design docs, and ``--level suggestion`` to see suggestion-level rules too:

::

    invoke lint-docs --path docs/cli-usage.rst
    invoke lint-docs --path docs/design

The lint is advisory: findings never fail the task, and it is not part of
pre-commit or CI. Reading ``.rst`` needs docutils' ``rst2html`` on
``PATH``; the development venv below has it (Sphinx depends on docutils).
Without it the task skips ``.rst`` files and says so. Rule changes belong in
``style_package``, not in a local override here.

Publishing a Release's Documentation
------------------------------------

Pushing a ``v*`` tag runs ``.github/workflows/release.yml``, whose ``docs``
job publishes that commit's rendered documentation under ``/<tag>/`` on the
GitHub Pages site. The directory is never replaced: a later deploy of the
same tag is refused, and every deploy from main copies each release
directory forward unchanged. After tagging a release:

1. Confirm ``https://brandon-arrendondo.github.io/aurora-lint/<tag>/index.html``
   is live and listed on ``versions.html``. The tag's docs job waits in the
   same queue as main's, and a newer push to main can cancel it while it
   waits. If it did, re-run that job from the tag's release run. Main's docs
   job also warns about any release whose directory is missing.
2. Never re-run a docs job from a run made before per-tag publishing
   existed, and never push to the ``gh-pages`` branch by hand. Either one
   publishes a site without the release directories. If that happens,
   restore them from an earlier ``gh-pages`` commit.

Development Node Setup
----------------------

To provision a fresh Ubuntu 24.04 node for working on aurora-lint (as opposed
to just running benchmarks -- see `Benchmark Setup <benchmark-setup.html>`_
for that), install Ansible first (``sudo apt install -y ansible`` or
``pipx install ansible-core`` -- a playbook can't provision the tool it
runs under), then run:

.. code-block:: bash

    ansible-playbook playbooks/setup-dev-environment.yml -i "localhost," -c local \
      --ask-become-pass

This installs the Rust toolchain (rustup, picking up the channel and
components pinned in ``rust-toolchain.toml``), the native build dependencies
``git2``'s vendored libgit2 build needs (a C toolchain, cmake, pkg-config),
and -- into a venv at ``~/.venvs/aurora-lint-dev`` by default -- the Sphinx + LaTeX
toolchain this guide itself is built with, ``invoke`` (for the
``invoke bump-version`` workflow), ``pre-commit`` (installed as this
checkout's git hook -- see the Git Commit Rules in AGENTS.md), and
``clew-trace`` (the package behind the ``clew-mcp`` command ``.mcp.json``
points at -- see CLAUDE.md's "Code Navigation (clew)" for registering the
MCP server itself with ``clew init``, a separate, per-machine step this
playbook does not run for you). Point the venv at an existing/shared one
instead with ``-e dev_venv=<path>``, e.g. ``-e dev_venv=~/venvs/shared``.

It also installs and schedules a disk-guard cron (``cargo-sweep`` +
``scripts/cargo-target-gc.sh``, hourly) that caps ``target/``
growth -- skip it on a node with plenty of headroom with
``-e install_disk_guard=false``. The script runs on macOS too (no
``flock`` there; it skips that one check), so a Mac node can take the same
``crontab`` line by hand, listing each worktree it builds in. This exists because two otherwise
identically-provisioned dev nodes were found to have diverged on exactly
this (2026-08-31): one had the cron, one didn't, and the one without it had
an unbounded ``target/`` and a manually-patched ``Cargo.toml`` disabling
dependency debug info as an ad hoc workaround.

It does not install comparison tools -- cppcheck and clang-tidy (apt
packages, see `Benchmark Setup <benchmark-setup.html>`_) or Infer/Frama-C
(``playbooks/install-static-analyzers.yml``) -- clone the real-world
benchmark checkouts or the Juliet test suite (also `Benchmark Setup
<benchmark-setup.html>`_ -- a node that only needs the benchmark code as
reference, not to run benchmarks, can skip both and just copy an existing
node's ``$SQC_BENCH_ROOT`` directory over), or install editor/terminal
conveniences (vim, htop, tmux). A node doing rule-development work that
compares aurora-lint's output against these tools' still needs
``install-static-analyzers.yml`` run separately -- none of that is a
dependency of building or testing aurora-lint *itself*, which is this playbook's
only scope.
