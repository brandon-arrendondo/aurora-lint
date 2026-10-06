Error Handling and Exit Codes
=============================

aurora-lint aims never to crash and never to run away, but it cannot
guarantee either. It is tested against the Juliet suite and a set of real
code bases, and real code eventually contains something no test covered.
This page explains what happens when a part of the analysis fails, how that
shows up in the output and the exit code, and what a CI pipeline should do
with it. The policy is recorded in ``docs/adr/0017-graceful-failure.md``.

The short version: a failure costs the one rule on the one file where it
happened, it is always reported, and it never passes as a clean scan.

Exit codes
----------

======  ======================================================================
Code    Meaning
======  ======================================================================
``0``   The scan completed. No finding reached a ``--fail-on-*`` threshold
        (or none was set).
``1``   The scan completed, and a finding reached ``--fail-on-violation`` or
        ``--fail-on-severity``.
``2``   The scan could not run: a usage or configuration error, such as a bad
        path, an invalid manifest or suppression file, or an unknown option.
``3``   The scan completed but is **incomplete**: some part of the analysis
        crashed or ran out of its budget. The findings it did produce are
        printed and exported; the ones the failed part would have produced
        are missing.
======  ======================================================================

``3`` takes precedence over ``1``, and is returned whether or not a
``--fail-on-*`` option is set. A scan with a rule missing is never reported
as clean.

What fails, and what it costs
-----------------------------

The analysis runs in units of work, and each is contained on its own:

- **One rule on one file.** If a rule fails on a file, its findings for
  that file are dropped. Every other rule's findings for that file, and all
  findings in other files, stand.
- **One file.** If reading, parsing or analysing a file fails outside any
  one rule, that file contributes no findings.
- **One input file that is not source** (see below): skipped before it is
  parsed.
- **One file's prescan.** If collecting a file's cross-file facts (function
  summaries, macros, declared allocators) fails, those facts are missing.
  That can change findings in *other* files, in either direction, which is
  why it is reported as its own stage. An incomplete prescan is never saved
  with ``--save-prescan``.

A rule that fails on **three** different files in one scan is **abandoned**
(and reported once, as abandoned, rather than once per file it reached):
it is skipped for the rest of the scan and *all* of its findings are
withheld, including those from files where it succeeded. A rule failing that
often cannot be trusted on this code base, and withholding all of its
findings keeps the output the same however the parallel scan happened to
order the work.

Files that are not source
-------------------------

aurora-lint picks files by extension, so anything named ``.c`` or ``.h`` is
offered to the parser. Before parsing, each file is checked:

- **too large**: larger than ``--max-file-size`` MiB (default 64; ``0``
  removes the limit). The largest real C files are amalgamations and SDK
  headers of about 10 MiB, so the default refuses only something that is not
  ordinary source.
- **not source text**: the file starts like a binary or an archive (ELF,
  PE, Mach-O, zip, gzip, xz, 7z, zstd, tar, PDF, an image, and so on), or
  its first 8 KiB has too many NUL, control or invalid-UTF-8 bytes to be
  text. This is a heuristic, tuned so that real C source is never refused.
  Files with a UTF-16 byte-order mark are text and are read normally, and
  empty files are fine.

A refused file is **skipped and reported**, never parsed, and the scan exits
``3``:

.. code-block:: text

    Error: input skipped (not source text): build/blob.c: looks like binary data (Elf, application/x-executable)
    Error: input skipped (too large): gen/table.c: 80 MiB is over --max-file-size 64 MiB

If the file belongs in the tree but is not source, leave it out of the scan
with ``--exclude-all``. Excluded files are not reported. Files over 8 MiB are
analysed one at a time, so that several of them are never in memory at once.

Crashes and bounds
------------------

A unit of work stops for one of four reasons, each reported the same way:

- **crashed**: an internal error (a Rust panic). Always an aurora-lint
  bug; please report it with the message and the ``[at ...]`` location.
- **step limit**: the unit reached its step budget, ``--rule-step-limit``
  (default 50,000,000). Steps are counted at the loops whose length the
  input decides, so the budget is deterministic: the same input stops at
  the same point on any machine. The default is far above anything the
  benchmark corpora reach, so hitting it means a runaway or an input far
  larger than anything measured.
- **time limit**: the unit ran longer than ``--rule-time-limit`` seconds
  (default 300). This is the backstop for what a step count cannot see.
- **analysis cap**: an analysis reached an iteration cap past which its
  results would not have converged.

Two analyses are known not to converge on some real code: the value-range
analysis and the initialization-state analysis. When either stops short,
the scan keeps what it has, as it always did. It prints a warning after the
findings and adds a SARIF ``warning`` notification. The exit code is not
changed:

.. code-block:: text

    Warning: value-range analysis did not converge 3 time(s); results there may be incomplete (a known issue, see docs/error-handling.rst)

These leave the list as their convergence is fixed.

Stopping early is never treated as "nothing found". An analysis that is cut
short has not shown that the code is safe, so treating it as safe would be
unsound. That is why a bound is reported exactly like a crash.

As a last resort, if a unit of work is still running at twice its time limit
(and at least a minute past it), aurora-lint names it on stderr and exits
``3`` without writing findings. This only happens for a loop that never
reaches a step checkpoint. It is always a bug.

``--rule-step-limit 0`` and ``--rule-time-limit 0`` remove the limits, if you
would rather wait for an unusually large input than have it reported.

How failures are reported
-------------------------

On stderr, after the findings, there is one line per failure, then a
summary:

.. code-block:: text

    Error: rule failure (crashed): MEM35-C: src/pool.c: begin > end (16 > 11) when slicing ... [at src/rules/cert_c/MEM/MEM35-C/mem35_c.rs:180:50]
    Error: rule failure (step limit): INT30-C: src/big.c: stopped after 50000000 steps (--rule-step-limit) [at ...]
    Error: file failure (crashed): src/odd.c: ... [at ...]
    Error: prescan failure (crashed): include/util.h: ... [at ...]
    Error: rule abandoned: MEM35-C: failed on 3 or more files; none of its findings are reported
    Error: scan INCOMPLETE: 4 unit(s) of work did not finish in 4 file(s) (rules INT30-C, MEM35-C); ...

The line formats are stable enough to parse.

In a **SARIF** export, the run's ``invocations[0]`` has
``executionSuccessful: false``, and each failure and abandoned rule is a
``toolExecutionNotifications`` entry at level ``error``. Each entry carries:

- ``descriptor.id``: ``aurora-lint/incomplete/rule``, ``.../file``,
  ``.../prescan`` or ``aurora-lint/rule-abandoned``;
- ``associatedRule`` and the file's location;
- ``properties.stage``, ``properties.cause`` and
  ``properties.sourceLocation``.

Code-scanning dashboards show these as tool errors. A complete scan has
``executionSuccessful: true`` and no notifications.

The **JSON** export is a list of findings only and does not change; for a
JSON consumer, the exit code is what says the list is incomplete.

What CI should do
-----------------

- Treat ``3`` as a failed job, separately from findings. The usual shell
  check, "fail on any nonzero status", already does. A script that tests
  for exactly ``1`` should handle ``3`` too:

  .. code-block:: bash

      aurora-lint . -d . --fail-on-severity High --export results.sarif
      case $? in
        0) echo "clean" ;;
        1) echo "findings at or above High"; exit 1 ;;
        3) echo "scan incomplete: see the 'Error:' lines above"; exit 1 ;;
        *) echo "aurora-lint could not run"; exit 1 ;;
      esac

- Keep the SARIF upload step running when the scan exits ``3``, for example
  with ``if: always()`` in GitHub Actions, so the findings that were
  produced still reach the dashboard alongside the tool error.
- Report a ``crashed`` line upstream. A ``step limit`` or ``time limit`` on
  unusually large generated code can be raised with ``--rule-step-limit`` /
  ``--rule-time-limit``. Raise it in the job, not by ignoring status ``3``.

Limits of this guarantee
------------------------

- A stack overflow aborts the process outright and cannot be contained.
  Analysis threads run on a large stack (16 MiB) so that deeply nested code
  does not reach it.
- Many internal analyses bound their own work by design. When a bound
  degrades to a *sound* approximation (for example widening a value range
  to the whole type, or "not proven, so report"), that is the analysis
  working as intended and is not reported. A small number of older bounds
  still stop silently. They are listed in
  ``docs/design/analysis-bounds-inventory.md``, and each is being converted
  either to a sound fallback or to a reported bound.
