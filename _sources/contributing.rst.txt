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
       cargo test --package sqc --lib -- rules::cert_c::RULE_ID::tests
       cargo fmt

Build Requirements
------------------

- **Rust**: 2021 edition (stable toolchain)
- **Platform**: Linux, macOS, Windows (cross-platform via crossterm)
- **Dependencies**: See ``Cargo.toml`` for the full list

::

    cargo build             # Debug build
    cargo build --release   # Release build (optimized)
    cargo test              # Run all tests
    cargo fmt               # Format code

Development Node Setup
----------------------

To provision a fresh Ubuntu 24.04 node for working on tools_sqc (as opposed
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
and -- into a venv at ``~/.venvs/sqc-dev`` by default -- the Sphinx + LaTeX
toolchain this guide itself is built with plus ``invoke`` (for the
``invoke bump-version`` workflow). Point it at an existing/shared venv
instead with ``-e dev_venv=<path>``, e.g. ``-e dev_venv=~/data-enterprise/venv``.

It does not install comparison tools (cppcheck, clang-tidy, Infer, Frama-C --
see `Benchmark Setup <benchmark-setup.html>`_), clone the real-world
benchmark checkouts, or install editor/terminal conveniences (vim, htop,
tmux) -- none of those are dependencies of building or testing sqc itself.
