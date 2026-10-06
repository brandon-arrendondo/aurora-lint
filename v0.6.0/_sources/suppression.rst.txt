Suppression System
==================

aurora-lint suppresses findings through inline source comments or an external
TOML file. A per-line suppression carries a hash of the violation line, so it
stops working when that line changes. A per-file or per-directory suppression
matches by path and rule instead.

Design intent: surface, don't silence
--------------------------------------

aurora-lint's job is to correctly surface every violation of a rule as the rule is written
-- not to guess which violations a given team will care about. Whether a correctly
detected finding is worth acting on, is a deliberate style choice, or applies to a
particular codebase at all is a per-project judgment call, and this suppression
system (plus per-project rule manifests, see :doc:`configuration`) is where that
judgment belongs -- not inside the rule's detection logic.

Concretely: if a rule check is *correct* (every reported finding is a real instance
of what the rule's text describes) but *noisy* for a given project or produces more
findings than expected after a detection improvement, the fix is a suppression
entry or a manifest change, with a justification -- not softening the rule so it
stops finding things. A rule that under-reports to avoid noise is failing at its
one job; a rule that over-reports on a project that doesn't want it is a
configuration problem, and configuration problems have a config-file answer.

.. _project-controls:

Scoping and suppressing findings: the four project controls
-----------------------------------------------------------

A project team decides what aurora-lint reports with four controls, from the
coarsest to the finest. aurora-lint never infers scope and never silences a
finding by itself. Every exclusion and every suppression is the project's own
declaration, written on its command line, in its manifest or suppression file,
or in its source. Each one should say why: a comment beside an excluded glob
or an ``enabled = false`` line, and the ``justification`` a suppression
carries.

1. **Exclude code from the scan.** Use this for code that is not the product:
   test harnesses, generated files, demo programs and build tooling.
   ``--exclude-all`` (or ``exclude_all`` in a manifest's ``[scope]`` table)
   leaves such files out of everything, including the cross-file facts other
   files are checked against. Vendored code the product links is different:
   its definitions are the ones the product's calls reach. Use
   ``--report-exclude`` for it, which reports nothing there but still reads it.
   :doc:`cli-usage` covers these and ``--prescan-exclude``::

       aurora-lint . --exclude-all 'tests/**' --report-exclude 'vendor/**'

2. **Disable a rule for the whole codebase.** Use this for a rule that cannot
   apply to the project, such as a Windows-only rule on a POSIX-only project,
   or one the team defers on purpose while it builds triage capacity. Set
   ``enabled = false`` on the rule in the project's manifest, with the reason
   in a comment. :ref:`relaxed-onboarding` explains when this is the right
   control and when it is not::

       [rules.cert_c.WIN30-C]
       enabled = false  # POSIX-only project: no Windows API calls

3. **Suppress per file or directory.** Use this when the files are scanned and
   their other findings matter, but one rule or rule family is known not to
   apply there. Add a `wildcard suppression`_: a suppression-file entry
   with no ``hash``, matched by ``file_glob`` together with ``rule``,
   ``rule_glob`` or ``function_prefix``::

       [[suppress]]
       name = "tests-mem"
       tool = "aurora-lint"
       file_glob = "tests/**"
       rule_glob = "MEM*"
       justification = "Test fixtures leak on purpose; the process exits"

4. **Suppress per line.** Use this for one finding the team has reviewed and
   accepted. Add an `inline comment suppression`_ above the line, or a
   hash-matched entry in the `external suppression file`_ when the source is
   read-only. Either one carries a hash of the line, so the suppression lapses
   when the line changes and the finding comes back for review::

       // AURORA-SUPPRESS: ARR30-C HASH:a1b2c3d4e5f67890 JUSTIFICATION: "Bounds validated by caller"

Excluding a file removes it before the scan. A suppressed finding is still
found: the summary line counts it, and a SARIF export keeps it with a
``suppressions`` entry holding its justification.

aurora-lint marks one kind of finding suppressed without a declaration: a
finding inside a preprocessor branch that is never compiled as C. That covers
``#if 0``, a ``__cplusplus``-only block, and a guard the file itself proves
false. No build compiles that code. The finding's justification says so, and
it is counted and exported like any other suppressed finding. A branch that
only some builds compile is not suppressed: every ``#ifdef`` arm is analysed
(see ``docs/adr/0010``).

Inline Comment Suppression
--------------------------

.. code-block:: c

    // Line-before style (most common):
    // AURORA-SUPPRESS: ARR30-C HASH:a1b2c3d4e5f67890 JUSTIFICATION: "Bounds validated by caller"
    arr[index] = value;

    // Inline style (same line as violation):
    arr[index] = value; // AURORA-SUPPRESS: ARR30-C HASH:a1b2c3d4e5f67890 JUSTIFICATION: "Bounds checked"

    // Stacked (multiple rules on one line):
    // AURORA-SUPPRESS: ERR00-C HASH:aaaa... JUSTIFICATION: "return captured in bytes_read"
    // AURORA-SUPPRESS: EXP34-C HASH:bbbb... JUSTIFICATION: "buf checked at function entry"
    bytes_read = fread(buf, 1, file_size, fp);

Generate the hash with:

::

    aurora-lint --generate-suppression src/main.c:42:ARR30-C

.. _suppression-legacy-spelling:

Pre-rename spellings (still accepted)
-------------------------------------

The tool was named ``sqc`` before it was renamed ``aurora-lint``. Every
suppression written under the old name keeps working, so no existing
suppression needs to be rewritten:

==========================================  ==========================================
Pre-rename                                  Current
==========================================  ==========================================
``// SQC-SUPPRESS: RULE ...``               ``// AURORA-SUPPRESS: RULE ...``
``// tools:suppress sqc:RULE ...``          ``// tools:suppress aurora-lint:RULE ...``
``tool = "sqc"`` in ``suppress.toml``       ``tool = "aurora-lint"``
``.sqc-suppress.toml``                      ``.aurora-lint-suppress.toml``
==========================================  ==========================================

Both spellings of a directive hash identically -- the hash covers only the code
portion of the line -- so renaming a comment in place does not invalidate it.
``--generate-suppression`` emits only the current spelling.

External Suppression File
-------------------------

For read-only codebases, place a ``suppress.toml`` in the project root -- the
shared, all-tools file -- or specify one with ``--suppress-file``. Failing that,
``.aurora-lint-suppress.toml`` and the pre-rename ``.sqc-suppress.toml`` are
auto-detected too, in that order.

Every entry is a ``[[suppress]]`` table. ``name`` labels the entry and
``tool`` says which tool it applies to: ``"aurora-lint"``, or ``"*"`` for every
tool that reads the file. aurora-lint ignores entries for other tools. An entry
with a ``hash`` suppresses one line; `wildcard suppression`_ covers an entry
without one.

.. code-block:: toml

    # suppress.toml

    [[suppress]]
    name = "ringbuffer-int30"
    tool = "aurora-lint"
    file = "ringbuffer.c"
    rule = "INT30-C"
    hash = "a1f5861150a1e5b8"
    justification = "Overflow checked by caller"

    [[suppress]]
    name = "utility-exp34"
    tool = "aurora-lint"
    file = "src/utility.c"
    rule = "EXP34-C"
    hash = "b2c3d4e5f6a78901"
    justification = "Pointer validated at function entry"

A hash-matched entry needs ``file``, ``rule`` and ``hash``;
``--generate-suppression`` prints one ready to paste. The ``file`` field
matches by path suffix: ``ringbuffer.c`` matches any path ending in
``/ringbuffer.c``.

aurora-lint reads only ``[[suppress]]`` tables. An invalid suppression file
stops the run with exit status 2, so a file is never read in part. A file is
invalid when it holds:

- a table under any other name, such as ``[[suppression]]`` or ``[[wildcard]]``;
- an entry with no ``name``;
- an entry with a key it does not take, such as ``reason`` in place of
  ``justification``;
- a ``hash`` entry without ``file`` and ``rule``;
- an entry with no ``hash`` and nothing to match on, which would suppress
  every finding.

The error names the file and every problem in it at once, with the allowed
keys. Entries are checked only when their ``tool`` is ``"aurora-lint"`` or
``"*"``, since another tool's entries in the shared file may carry keys only
that tool reads. A file that is not valid TOML stops the run the same way.

Wildcard Suppression
--------------------

To suppress findings by path and rule without per-line hashes, leave out
``hash``. The fields present are ANDed, so a violation must match every one
of them, and at least one of ``file_glob`` (or ``file``), ``rule``,
``rule_glob`` and ``function_prefix`` must be set.

.. code-block:: toml

    # Suppress one rule for every file under a directory
    [[suppress]]
    name = "vendor-dcl31"
    tool = "aurora-lint"
    file_glob = "src/vendor/**"
    rule = "DCL31-C"
    justification = "Vendor code, not our responsibility"

    # Suppress a rule family for the same directory
    [[suppress]]
    name = "vendor-dcl"
    tool = "aurora-lint"
    file_glob = "src/vendor/**"
    rule_glob = "DCL*"
    justification = "All DCL rules suppressed for vendor code"

    # Suppress by a function name prefix in violation messages
    [[suppress]]
    name = "wolfssl-dcl31"
    tool = "aurora-lint"
    rule = "DCL31-C"
    function_prefix = "wolfSSL_"
    justification = "wolfSSL library functions declared in external headers"

    # Combine conditions (all must match)
    [[suppress]]
    name = "tests-mem"
    tool = "aurora-lint"
    file_glob = "tests/**"
    rule_glob = "MEM*"
    justification = "Memory rules relaxed in test code"

Vendored code the product links can also be left out of the report entirely
with ``--report-exclude`` (see :ref:`project-controls`). A wildcard entry is
for code whose other findings you still want.

**Fields:**

- ``name`` — A label for the entry, unique within the file (required).
- ``tool`` — ``"aurora-lint"``, or ``"*"`` for every tool (required).
- ``file_glob`` — Glob pattern for file paths. Supports ``*`` (any characters
  except ``/``), ``**`` (any characters including ``/``), and ``?`` (single
  character). Matched as a suffix against the full file path. Without
  ``file_glob``, a ``file`` value is used as the pattern.
- ``rule`` — Exact rule ID match (e.g., ``"DCL31-C"``).
- ``rule_glob`` — Glob pattern for rule IDs (e.g., ``"DCL*"``, ``"INT3?-C"``).
- ``function_prefix`` — Prefix to match in violation messages. Matches at word
  boundaries, so ``"wolfSSL_"`` matches ``'wolfSSL_Init'`` but not
  ``'myWolfSSL_Init'``.
- ``justification`` — Why the findings are suppressed. A SARIF export records
  it with each suppressed finding.

Wildcard suppressions are checked after inline comment and hash-matched
suppressions. Hash-matched suppressions always take priority.

Hash Details
------------

- **Algorithm**: ``SHA-256(rule_id + ":" + whitespace_normalized(violation_line))``,
  truncated to 16 hex characters
- **Rule-scoped**: different rules on the same line produce different hashes
- **Proximity matching**: inline comments match within 5 lines before the violation
- **Staleness detection**: if the violation line changes, the hash no longer matches
  and the suppression stops working, forcing re-review
