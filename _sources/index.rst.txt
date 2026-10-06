============================
aurora-lint Developer Guide
============================

aurora-lint is a terminal-based static analysis tool that validates
C code compliance with `SEI CERT C Coding Standards
<https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard>`_.
It tracks |rules_total| rules (|rules_enabled| implemented and enabled by default) across 17 CERT C categories, using tree-sitter for fast
AST-based analysis with cross-file context, control-flow graphs, and
inter-procedural reasoning.

This guide covers advanced usage, CI/CD integration, the interactive console UI,
testing methodology, project internals, and contributing.

These pages describe the main branch and change with it. Each release's
documentation stays published under its tag, as it read when the release was
made, and the `documentation versions
<https://brandon-arrendondo.github.io/aurora-lint/versions.html>`_ page lists
them. To cite a page, cite the release's copy, whose text and numbers never
change: ``https://brandon-arrendondo.github.io/aurora-lint/<tag>/<page>.html``,
for example ``.../aurora-lint/v0.6.0/configuration.html``.

Brandon Arrendondo is the accountable BISSELL Associate for aurora-lint, its maintainer, and the author of its documentation.

.. toctree::
   :maxdepth: 3
   :caption: Contents

   cli-usage
   suppression
   configuration
   options
   cicd-integration
   error-handling
   interactive-ui
   testing-methodology
   tool-comparison
   juliet-history
   architecture
   benchmark-setup
   benchmark-running
   reproducing-published-numbers
   measurement-notes
   project-structure
   future-rulesets
   contributing
   licensing
   bibliography
