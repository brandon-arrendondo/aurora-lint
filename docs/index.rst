========================
SqC Developer Guide
========================

SqC (Software Code Quality) is a terminal-based static analysis tool that validates
C code compliance with `SEI CERT C Coding Standards
<https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard>`_.
It implements 285 rules across 17 CERT C categories, using tree-sitter for fast
AST-based analysis with cross-file context, control-flow graphs, and
inter-procedural reasoning.

This guide covers advanced usage, CI/CD integration, the interactive console UI,
testing methodology, project internals, and contributing.

.. toctree::
   :maxdepth: 3
   :caption: Contents

   cli-usage
   suppression
   configuration
   cicd-integration
   interactive-ui
   testing-methodology
   architecture
   benchmark-setup
   benchmark-running
   project-structure
   future-rulesets
   contributing
   bibliography
