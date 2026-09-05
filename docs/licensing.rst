Licensing and content provenance
================================

This page exists for one audience: someone deciding whether sqc can enter a
distribution archive. It answers *what is in this source tree, who wrote it,
and under what terms*.

Summary
-------

.. list-table::
   :header-rows: 1
   :widths: 34 22 44

   * - Material
     - License
     - Where it lives
   * - sqc's own source, docs and packaging
     - ``Apache-2.0``
     - everything not listed below
   * - SEI CERT C rule titles and rule prose
     - ``CC-BY-4.0``
     - ``metadata.title`` / ``metadata.description`` in
       ``src/rules/cert_c/*/*/<RULE-ID>.toml``, and the ``description()``
       string in each rule's ``.rs``
   * - SEI CERT C code examples
     - ``MIT``
     - the C snippets embedded in those ``description`` fields, and the
       wiki-derived fixtures under ``src/rules/cert_c/*/*/tests/``

The single SPDX expression for the whole work, and for any binary package
built from it, is::

   Apache-2.0 AND MIT AND CC-BY-4.0

The binary is covered too, not just the tarball: each rule compiles its CERT
title in as a ``&'static str``, so a stripped ``sqc`` executable still carries
CC BY 4.0 material and still owes attribution.

The CERT terms
--------------

``thirdparty/cert/LICENSE`` holds, verbatim and unedited, the notice published
by the SEI itself at
https://github.com/cmu-sei/secure-coding-standards/blob/main/LICENSE. Its
operative sentence:

   The SEI CERT® Coding Standards are licensed under a Creative Commons BY 4.0
   Attribution License [...], and the code examples contained therein are
   licensed under a MIT license [...]. Although the rights granted by the
   referenced licenses allow modification [...]

Both are DFSG-free and Fedora-allowed, and both permit modification — which
matters, because sqc's rule descriptions *are* modified (they are extracted
from page markup and reflowed, and CC BY 4.0 section 3(a)(1)(B) requires that
modification be indicated).

.. warning::

   The SEI publishes a **second, restrictive notice** on its *technical
   reports* — reproduce-in-entirety-only, no modification, commercial use by
   permission. That notice is non-free and it does **not** govern the coding
   standards. An adjudication that quotes the technical-report boilerplate at
   this material has cited the wrong document and will reach the wrong answer.
   The standards' own ``LICENSE``, mirrored in ``thirdparty/cert/``, is the
   governing text.

Trademark, which is separate from copyright
-------------------------------------------

*Carnegie Mellon* and *CERT* are registered trademarks of Carnegie Mellon
University. The copyright licenses above grant nothing here.

- Nominative use in prose is fine: "sqc checks C code against the SEI CERT C
  Coding Standard" describes what the tool does and is how the marks may be
  used.
- **Do not put CERT or Carnegie Mellon in the binary name, the package name,
  or any name that reads as a source identifier.** The binary and the
  distribution package are both ``sqc`` deliberately. ``src/rules/cert_c/``
  is an internal path, not a published name.
- Do not imply endorsement, certification, or affiliation.

What a packager needs to write
------------------------------

Debian ``debian/copyright`` (DEP-5) needs three stanzas rather than one:

.. code-block:: none

   Files: *
   Copyright: <holder>
   License: Apache-2.0

   Files: src/rules/cert_c/*/*/tests/*
   Copyright: Carnegie Mellon University
   Comment: Fixtures derived from the SEI CERT C Coding Standard's compliant
    and non-compliant code examples. See thirdparty/cert/LICENSE.
   License: Expat

   Files: src/rules/cert_c/*/*/*-C.toml
   Copyright: Carnegie Mellon University
   Comment: metadata.title and metadata.description are lifted from the SEI
    CERT C Coding Standard and reflowed. Embedded C snippets are Expat.
   License: CC-BY-4.0 and Expat

The fixture stanza is deliberately broader than reality — roughly a third of
the fixtures are locally authored rather than wiki-derived, and each declares
which it is in a ``Source:`` header comment. Claiming CMU copyright over all
of them is the conservative direction to be wrong in; splitting the glob
requires the provenance audit tracked separately in the backlog.

Fedora ``.spec``: ``License: Apache-2.0 AND MIT AND CC-BY-4.0``. This is what
``.github/workflows/release.yml`` now emits.

Re-deriving the counts
----------------------

Provenance is recorded in the files themselves, so the split can be recounted
at any commit rather than trusted from prose:

.. code-block:: bash

   # rule manifests carrying CERT title/description text
   find src/rules -name '*-C.toml' | wc -l

   # fixtures declaring wiki provenance in their header comment
   grep -rl '^ \* Source: wiki' --include='*.c' src/rules | wc -l

As of 2026-09-05: 313 rule manifests, every one carrying a CERT title and
description, 310 citing their source wiki page, 33 embedding a CERT code
example; and 1,337 of 3,578 fixtures declaring wiki provenance.

Third-party Rust dependencies
-----------------------------

Unrelated to the above and handled separately: ``cargo-about`` generates
``THIRD_PARTY_LICENSES.txt`` and ``cargo-cyclonedx`` a CycloneDX SBOM on every
release build. Both ship in every release artifact. The allowlist of
acceptable dependency licenses is ``about.toml``.
