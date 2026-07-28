Suppression System
==================

SqC supports suppressing false positives via inline source comments or an external
TOML file. Each suppression includes a SHA-256 hash of the violation line, ensuring
suppressions break automatically when the underlying code changes.

Design intent: surface, don't silence
--------------------------------------

SqC's job is to correctly surface every violation of a rule as the rule is written
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

Inline Comment Suppression
--------------------------

.. code-block:: c

    // Line-before style (most common):
    // SQC-SUPPRESS: ARR30-C HASH:a1b2c3d4e5f67890 JUSTIFICATION: "Bounds validated by caller"
    arr[index] = value;

    // Inline style (same line as violation):
    arr[index] = value; // SQC-SUPPRESS: ARR30-C HASH:a1b2c3d4e5f67890 JUSTIFICATION: "Bounds checked"

    // Stacked (multiple rules on one line):
    // SQC-SUPPRESS: ERR00-C HASH:aaaa... JUSTIFICATION: "return captured in bytes_read"
    // SQC-SUPPRESS: EXP34-C HASH:bbbb... JUSTIFICATION: "buf checked at function entry"
    bytes_read = fread(buf, 1, file_size, fp);

Generate the hash with:

::

    sqc --generate-suppression src/main.c:42:ARR30-C

External Suppression File
-------------------------

For read-only codebases, place a ``.sqc-suppress.toml`` in the project root
(auto-detected) or specify with ``--suppress-file``:

.. code-block:: toml

    # .sqc-suppress.toml

    [[suppression]]
    file = "ringbuffer.c"
    rule = "INT30-C"
    hash = "a1f5861150a1e5b8"
    justification = "Overflow checked by caller"

    [[suppression]]
    file = "src/utility.c"
    rule = "EXP34-C"
    hash = "b2c3d4e5f6a78901"
    justification = "Pointer validated at function entry"

The ``file`` field matches by suffix -- ``ringbuffer.c`` matches any path ending
in ``ringbuffer.c``.

Wildcard Suppression
--------------------

For suppressing entire categories of violations without per-line hashes, use
``[[wildcard]]`` entries. All specified fields are ANDed — a violation must match
every field present. At least one matching field must be set.

.. code-block:: toml

    # Suppress a rule for all files under a directory
    [[wildcard]]
    file_glob = "src/vendor/**"
    rule = "DCL31-C"
    justification = "Vendor code, not our responsibility"

    # Suppress all DCL rules for vendor code
    [[wildcard]]
    file_glob = "src/vendor/**"
    rule_glob = "DCL*"
    justification = "All DCL rules suppressed for vendor code"

    # Suppress by function name prefix in violation messages
    [[wildcard]]
    rule = "DCL31-C"
    function_prefix = "wolfSSL_"
    justification = "wolfSSL library functions declared in external headers"

    # Combine multiple conditions (all must match)
    [[wildcard]]
    file_glob = "tests/**"
    rule_glob = "MEM*"
    justification = "Memory rules relaxed in test code"

**Fields:**

- ``file_glob`` — Glob pattern for file paths. Supports ``*`` (any characters
  except ``/``), ``**`` (any characters including ``/``), and ``?`` (single
  character). Matched as a suffix against the full file path.
- ``rule`` — Exact rule ID match (e.g., ``"DCL31-C"``).
- ``rule_glob`` — Glob pattern for rule IDs (e.g., ``"DCL*"``, ``"INT3?-C"``).
- ``function_prefix`` — Prefix to match in violation messages. Matches at word
  boundaries, so ``"wolfSSL_"`` matches ``'wolfSSL_Init'`` but not
  ``'myWolfSSL_Init'``.
- ``justification`` — Explanation for the suppression (required).

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
