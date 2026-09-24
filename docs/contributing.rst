Contributing
============

Adding a New CERT C Rule
------------------------

1. Create the rule directory and implementation file:

   ::

       src/rules/cert_c/CATEGORY/RULE-ID/rule_id_c.rs

2. Implement the ``CertRule`` trait:

   .. code-block:: rust

       use crate::prelude::*;

       pub struct Mem30C;

       impl CertRule for Mem30C {
           fn rule_id(&self) -> &'static str {
               "MEM30-C"
           }

           fn description(&self) -> &'static str {
               "Do not access freed memory"
           }

           fn check(
               &self,
               node: &Node,
               source: &str,
               _context: &ProjectContext,
           ) -> Vec<RuleViolation> {
               // Implementation here
               Vec::new()
           }
       }

3. Register the rule in ``src/rules/cert_c/mod.rs``.

4. Add test cases as ``.c`` files in ``src/rules/cert_c/CATEGORY/RULE-ID/tests/fail/``
   and ``tests/pass/``.

5. Add the rule entry to ``rules_templates/rules-all.toml``.

6. Build and test:

   ::

       cargo build
       cargo test --package aurora-lint --lib -- rules::cert_c::RULE_ID::tests
       cargo fmt

Build Requirements
------------------

- **Rust**: 2021 edition (stable toolchain)
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
checkout's git hook -- see CLAUDE.md's "Git Commit Rules"), and
``clew-trace`` (the package behind the ``clew-mcp`` command ``.mcp.json``
points at -- see CLAUDE.md's "Code Navigation (clew)" for registering the
MCP server itself with ``clew init``, a separate, per-machine step this
playbook does not run for you). Point the venv at an existing/shared one
instead with ``-e dev_venv=<path>``, e.g. ``-e dev_venv=~/data-enterprise/venv``.

It also installs and schedules a disk-guard cron (``cargo-sweep`` +
``scripts/cargo-target-gc.sh``, nightly at 03:30) that caps ``target/``
growth -- skip it on a node with plenty of headroom with
``-e install_disk_guard=false``. This exists because two otherwise
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
