Upgrading
=========

This page lists what a project scanning with one release has to check or
change to move to the next. The `changelog
<https://github.com/brandon-arrendondo/aurora-lint/blob/main/CHANGELOG.md>`_
lists every change; this page covers only the ones that can change a CI
result, a configuration file or a suppression.

From 0.6.0 to 0.7.0
-------------------

Configuration files and command lines
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

No command-line option or manifest key was removed. A 0.6.0 manifest,
suppression file and command line load under 0.7.0 unchanged, apart from the
warnings for removed rules described below.

The reverse doesn't hold. 0.6.0 refuses a manifest with a key it doesn't
know, so a manifest that uses anything new in 0.7.0 stops loading under
0.6.0: ``profile = "pedantic"``, ``c_standard``, ``posix_version``,
``libc_version``, ``libc = "newlib-nano"`` or ``[environment.threads]``. If
several machines or pipelines share one
manifest, move them to 0.7.0 together, or pin the version in CI.

Exit status 3
~~~~~~~~~~~~~

0.7.0 adds exit status ``3``: the scan finished but is incomplete, because a
rule, a file or a file's prescan crashed or ran out of its budget, or an
input file was skipped. It takes precedence over ``1``, and is returned
whether or not ``--fail-on-violation`` or ``--fail-on-severity`` is set. A
CI step that tests for exactly ``1`` to mean "findings" should also handle
``3``. See :doc:`error-handling`.

The strict preset
~~~~~~~~~~~~~~~~~

In 0.6.0, ``--profile strict`` meant the strict policy on a freestanding
environment with no library model. In 0.7.0 it means the strict policy on a
hosted environment that assumes only ISO C:

- The ISO C library contracts are trusted unless you declare a different
  ``libc``: ``free(NULL)`` does nothing, ``exit``, ``abort`` and ``longjmp``
  don't return, and ``main``'s ``argv`` is valid. Findings that relied on
  distrusting them go away.
- POSIX contracts and exemptions apply only when POSIX is declared, with
  ``posix_version`` in the manifest or through ``--compile-commands``. A
  strict scan of POSIX code that declares neither reports what those
  exemptions used to withhold, and says which fact is missing.

To keep 0.6.0's strict reading, declare the environment in the manifest:

.. code-block:: toml

    profile = "strict"

    [environment]
    kind = "freestanding"

To give a strict scan of POSIX code its POSIX exemptions, declare the
edition:

.. code-block:: toml

    [environment]
    posix_version = "2008"

See *Policy and Environment Settings* in :doc:`configuration`.

The data model under the default preset
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

0.6.0 credited only the integer widths ISO C guarantees when no data model
was declared, under every preset. In 0.7.0 the default preset assumes LP64
on a hosted target (32-bit ``int``, 64-bit ``long`` and pointers), so
findings that only occur with a 16-bit ``int``, such as ``1024 * 1024`` or
``1U << 31``, are no longer reported by default. The strict preset still
credits only the ISO C widths.

For a target whose ``int`` is 16 bits, declare it, and the default preset
reports those findings again:

.. code-block:: toml

    [environment]
    int_bits = 16          # or a data_model, or -m32/-m64 in a compile database

Removed, renamed and withheld rules
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A manifest block, a ``--rules`` list or a suppression that names a rule 0.7.0
no longer ships still loads. It prints one warning naming the release that
removed the rule and the rules that cover it, and it no longer matches
anything. ``--list-rules`` lists every shipped rule and every removed one
with its reason.

- **Renamed.** Three checks were never CERT C identifiers and now report under
  CWE ids, unchanged: MSC42-C is CWE-327, POS55-C is CWE-666 and WIN05-C is
  CWE-428. WIN05-C's registry check is now CWE-272 and reports only a write
  under ``HKEY_LOCAL_MACHINE`` or ``HKEY_CLASSES_ROOT``. Rename these ids in
  manifests, ``--rules`` lists and suppressions, or they stop matching.
- **Removed.** FIO50-C, FIO51-C and CON50-C (CERT C++ identifiers; FIO39-C,
  FIO42-C, and CON31-C with CON34-C report the same constructs), DCL22-C
  (SIG31-C reports a signal handler's non-volatile shared object, and MSC22-C
  a local changed between ``setjmp`` and ``longjmp``), and ERR06-C, FIO03-C,
  FLP05-C, INT14-C, MSC14-C, PRE12-C, PRE13-C and STR03-C. A suppression for
  one of these can be deleted.
- **Moved.** A double ``fclose()`` is reported by FIO46-C, not FIO24-C, and a
  double ``close()``, ``closesocket()`` or ``CloseHandle()`` is no longer
  reported. Move FIO24-C suppressions for a double ``fclose()`` to FIO46-C.
- **Withheld.** EXP30-C, FIO01-C, FIO08-C, FIO30-C, FIO32-C, FLP32-C,
  INT15-C, MEM35-C, STR34-C and WIN30-C don't run by default until they are
  rewritten, because they can report constructs that aren't in the code.
  DCL11-C doesn't run by default until it is removed, because its type check
  guesses an argument's type from its name. MSC39-C doesn't run by default
  until it detects the caller's use of a ``va_list`` after passing it by
  value; it reported the callee that receives the list, which is permitted.
  To keep running one, enable it in a manifest. Naming a withheld rule in
  ``--rules`` without enabling it prints a warning instead of giving a clean
  report.

Declarations the scan now needs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

EXP33-C treats a call as an allocation only when the callee is a standard
allocator or one you declare. A wrapper is no longer taken for an allocator
because its name contains ``malloc``, ``calloc`` or ``realloc``, or because
it returns ``realloc``'s result. Declare such wrappers to keep their
findings:

.. code-block:: toml

    [environment.allocators]
    xmalloc = "malloc"     # follows malloc's contract

0.6.0 made the same change for deallocators; ``--report-deallocator-candidates``
lists the callees that would change a finding.

Suppressions that move
~~~~~~~~~~~~~~~~~~~~~~

A per-line suppression carries a hash of the finding's line
(:doc:`suppression`), so a finding that now lands on a different line leaves
its suppression unused and is reported again. In 0.7.0, PRE01-C reports each
unparenthesized use of a macro parameter where it is written, not once per
parameter at the ``#define``. EXP19-C reports each unbraced ``if``,
``else``, ``for`` and ``while`` body where the body starts, not at its
keyword. Regenerate PRE01-C and EXP19-C suppressions with
``--generate-suppression``.

Saved prescan caches and the settings hash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A prescan cache saved by 0.6.0 (``--save-prescan``) is refused by 0.7.0
with a message to re-create it. Save it again with 0.7.0.

The settings hash now covers each preset's column of the per-rule preset
table, so every preset's settings hash changes once at 0.7.0 with nothing
else changed. A trend or baseline keyed on the hash starts again from 0.7.0.

Severities
~~~~~~~~~~

Five rules now report at the severity CERT gives them, which can move a
finding across a ``--fail-on-severity`` threshold: MSC37-C is High (was
Medium), FIO21-C is Medium (was High), INT33-C and STR30-C are Low (were
High), and FIO14-C is Low (was Medium).

``--diff``
~~~~~~~~~~

``--diff PATH`` now refuses, with exit status ``2``, a path that isn't the
root of a git repository. In 0.6.0 it silently scanned every C file there.
In a pull-request job, the new ``--diff-base REF`` scans what the branch
changed since its merge base with ``REF``.
