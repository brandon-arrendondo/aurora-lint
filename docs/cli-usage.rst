Advanced CLI Usage
==================

Command Reference
-----------------

``aurora-lint --help`` lists every option, with its default and allowed values
where it has them, and :doc:`options` lists every policy and environment option.
The manual page, ``docs/aurora-lint.1`` (``man -l docs/aurora-lint.1`` in a
checkout), is the standalone reference. The sections below cover how the
options work together.


Cross-File Analysis
-------------------

Cross-file context comes from a pre-scan that collects function definitions,
type declarations, and macro aliases before analysis begins. This
significantly reduces false positives from rules like DCL31-C (unused identifiers)
and DCL07-C (type mismatches) that would otherwise flag externally-defined symbols.

With no ``-d``, the target is pre-scanned itself: every ``.c``/``.h`` file under
a directory target, or the file plus the headers beside it for a single-file
target. So ``aurora-lint foo.c`` already knows the definitions in ``foo.c``,
and ``aurora-lint src/`` knows everything under ``src/``, without naming the
target a second time.

The ``-d`` / ``--directories`` flag adds context from *outside* the target.
Once any ``-d`` is given, the pre-scan covers exactly the ``-d`` directories:
name the target too if its own definitions should stay in scope.

::

    # The target is its own context; nothing more needed
    aurora-lint /path/to/project

    # Include additional directories (e.g., shared headers, sibling modules)
    aurora-lint /path/to/project -d /path/to/project -d /path/to/shared/headers

    # Multiple -d flags stack — all are pre-scanned before analysis begins
    aurora-lint src/ -d src/ -d vendor/ -d third_party/

The pre-scan collects:

- **Function definitions**: names, parameter counts, return types across all ``.c``/``.h`` files
- **Header prototypes**: functions declared in ``.h`` files (public API detection for DCL15-C)
- **Function summaries**: null return behavior, freed parameters, no-return annotations,
  parameter dereferences, return value ranges, parameter pass-through chains
- **Call graph**: caller → callee relationships for transitive analysis
- **Call-site argument states**: null state of arguments at each call site, aggregated
  per parameter for inter-procedural null propagation
- **Macro constants and aliases**: ``#define`` values for constant evaluation and
  ``#define SYSTEM system`` patterns for taint tracking
- **Struct field types**: struct definitions for type resolution (INT32-C, INT30-C)
- **Global constants**: file-scope ``const`` variables for dead-branch elimination
- **Global pointer null states**: cross-file ``extern`` pointer tracking (EXP34-C)


Using a Compile Database
------------------------

aurora-lint needs no build system: point it at any tree and it works. ``--compile-commands``
is a purely optional upgrade for projects that *already* produce a
``compile_commands.json`` (CMake's ``CMAKE_EXPORT_COMPILE_COMMANDS``, ``bear``,
``compiledb``). Without the flag, nothing changes.

::

    aurora-lint src/ -d src/ --compile-commands build/compile_commands.json

aurora-lint does **not** run a preprocessor. It reads three things out of the database
and feeds them to the pre-scan that already exists:

- **Include search paths** (``-I``, ``-isystem``, ``-iquote``, ``-idirafter``,
  resolved against each entry's ``directory``) are appended to any explicit
  ``-I`` you passed. This lets ``#include`` resolution reach headers the
  sibling-header scan would never find — notably angle-bracket includes of
  vendored or out-of-tree headers — so their macros, prototypes and struct
  types join the cross-file context.
- **Command-line macros** (``-D``, minus anything ``-U``'d) are parsed as real
  ``#define`` directives, so command-line constants fold and function-like
  ``-D`` macros become expandable exactly like ones written in a header.
- **The build's macro state** (the same ``-D``/``-U`` flags, read for
  definedness rather than for value) tells aurora-lint which ``#if`` arms that
  build compiles. Without a database, a file that defines one name under
  several mutually exclusive conditions is arbitrated by a POSIX platform guess
  plus first-wins; with one, the arms your build cannot compile are skipped, so
  the definition kept is the one you actually build. A ``#define`` in real
  source still overrides the flag, as it does for macro values.

This last one only affects **which definition a name resolves to**. It never
decides whether a finding is reported: a violation inside an ``#ifdef`` arm your
build does not select is still reported, because some other build selects it
(see ``docs/adr/0010``). There is deliberately no flag that suppresses findings
by configuration.

One consequence worth knowing, which aurora-lint warns about: the declaration
applies to the whole scan, while a database describes the translation units the
build compiles. If you scan sources that build does *not* compile — another
platform's backend, a feature the configuration disables — they are still
analysed, but their macros resolve under a configuration that excludes them, so
a name defined only in an arm that configuration rules out may not resolve at
all. The warning names how many scanned ``.c`` files the database does not
cover. Scanning the sources your database compiles avoids it.

Because the parse tree is untouched, every finding keeps the source location it
always had, and the ``PRE*`` rules still audit macros as written.

**Databases from an MSVC build.** An entry compiled by ``cl``, ``clang-cl`` or
a driver given ``--driver-mode=cl`` is read with cl's own syntax. Options may be
spelled with ``/`` or ``-``: ``/D`` (including cl's ``NAME#VALUE`` form),
``/U``, ``/I``, ``/imsvc`` and ``/external:I``, each attached or as a separate
argument. ``/FI`` forced includes are resolved before any header the sources
include, in command-line order. Arguments after ``/link`` or clang-cl's ``--``
are ignored, as are cl options that do not affect headers or macros. The driver
is recognised behind a compiler launcher (``sccache``, ``ccache``, …). A
``command`` string written on Windows is split with the MSVC C runtime's
quoting rules, and ``@file`` response files (UTF-8 or UTF-16) are expanded for
any driver. For every other driver the ``/`` spellings are not
read, so a POSIX path such as ``/Users/me/a.c`` is never taken for ``/U``.

cl finds the Windows SDK and CRT headers through the ``INCLUDE`` environment
variable, not through flags, so a cl database lists none of them. Pass those
directories with ``-I``. The database also keeps the Windows paths it was
written with: scanning from WSL or another host needs them remapped, and
aurora-lint warns when its include paths do not exist.

Windows looks file names up ignoring case, so a Windows project can spell a
header ``<Shlobj.h>`` or ``COMMCTRL.H`` when the file on disk is ``ShlObj.h`` or
``CommCtrl.h``. A cl database therefore makes ``#include`` matching
case-insensitive, one path component at a time; ``--include-names exact`` (or
``include_names`` in the manifest, see :doc:`configuration`) turns that off, and
``--include-names case-insensitive`` turns it on without a database. An entry
whose name matches exactly still wins. When a directory holds several different
files that differ only in case, the first in byte order is read. Each header
found only by ignoring case, and each such ambiguity, is listed by
``--report-macro-gaps``, so a spelling that only a Windows build tolerates is
visible. Two things are still matched exactly: a ``/FI`` name, which is looked
up beside the database entry only when it is spelled as on disk, and the file
names in ``#include "x.c"`` that decide which ``.c`` files are compiled into
another. A ``--save-prescan`` cache records the rule it was built under, and
``--load-prescan`` refuses it under the other one.

Reaching the Compiler's Own Headers
-----------------------------------

A compile database lists the flags a build *passes*, so it can never contain the
compiler's built-in search directories — the compiler already knows them.
``--system-includes`` recovers them by asking the compiler itself
(``cc -E -Wp,-v -``) and appending what it reports, lowest priority, after
everything you or the database named::

    aurora-lint src/ -d src/ --system-includes
    aurora-lint src/ -d src/ --compile-commands build/compile_commands.json --system-includes

With a compile database, each distinct compiler the database names is asked (so
a cross-compiled project gets *its* toolchain's directories); without one, the
platform default ``cc`` is asked. A compiler that cannot be run — a
cross-compiler absent from the analysis host, say — produces a warning and is
skipped, never an error.

It is off by default for two reasons: it spawns a compiler, which the rest of
the analysis pipeline never does, and it is worth being able to measure its
effect separately from the database's.

What it actually reaches, on a typical Linux host, is the two directories
nothing else does. ``/usr/include`` is commonly passed by hand already, but the
multiarch directory (``/usr/include/x86_64-linux-gnu``) holds glibc's
``bits/*.h``, so a ``<bits/...>`` include from an otherwise-reachable header
dead-ends without it; and the gcc internal directory is where ``stdarg.h``,
``stddef.h`` and ``stdbool.h`` *actually* live, since glibc does not ship them.
Without the flag, ``NULL``, ``offsetof``, ``va_list`` and ``bool``/``true``/
``false`` are never harvested from their real definitions.

One caveat worth knowing: ``#include`` resolution lets a later header's macro
override an earlier one of the same name, so pointing it at the whole system
header tree allows a libc macro to win over a project macro that shares its
name. That is how any ``-I`` path has always behaved; this flag is simply the
first thing to aim it at all of ``/usr/include``.

Two properties worth knowing:

- **Build flags never override real source.** A ``-D`` only supplies a macro
  name the scanned tree never defined; a real ``#define`` always wins.
- **Paths are absolute and host-specific.** A database generated on another
  machine or inside a container names directories that may not exist locally.
  aurora-lint warns when compile-database include paths are missing rather than
  silently resolving nothing.

The compiler's own built-in system header directories are *not* in a compile
database (they are implicit); ``--system-includes`` (above) adds them.

Headers the Scan Could Not Find
-------------------------------

A header the scan cannot find changes what it can see: the declarations,
macros and function bodies that header would supply are missing, and findings
that rely on them can differ from a scan on a host that has the header. So a
missing header is never silent. Whenever an ``#include`` in code some
configuration compiles resolves to no file, aurora-lint prints one line on
stderr naming how many headers were not found and the first few of them; with
``-v`` it lists each one with the file and line that includes it and the
search path it was looked up on. An ``#include`` inside an arm its own file
proves is never compiled (``#if 0``) is counted, not listed, and one written
only inside a system header (often a platform arm, such as a NetWare-only
include in a Linux library header) is listed apart from the project's own.

Headers that live in the compiler's built-in directory or the multiarch
directory rather than in ``/usr/include`` itself (the ``bits/``, ``gnu/`` and
``asm/`` trees and the freestanding headers such as ``stddef.h`` and
``stdarg.h``) are counted apart and not headlined: the scan searches those
directories only with ``--system-includes``, so without it nearly every host
misses them, and they would drown out the project's own missing headers.
``-v`` and ``--report-headers`` still list each one. A missing header of the
project's own that happens to share such a name (a generated ``asm/...``) is
headlined as usual. On a Linux scan without ``--system-includes`` this line
is therefore almost always printed; what matters is which headers it names.

To pin what a scan sees instead of explaining it afterwards, give it the
headers explicitly, all opt-in: ``-I`` for each directory (the multiarch one
included), ``--system-includes`` for the compiler's own, or a fixed header
tree checked out alongside the project.

The SARIF export records the same rows under the run's
``aurora-lint/headers`` property, with a ``note``-level
``toolExecutionNotifications`` entry: a missing header is a difference in the
scan's input, not an incomplete scan, so the run stays successful and the exit
status is unaffected. ``--report-headers FILE`` writes everything as JSON,
including each header read from outside the project with its SHA-256, so the
reports of two hosts diff to the header that explains a difference in their
findings::

    aurora-lint src/ -d src/ -I include/ -I /usr/include --report-headers headers.json

Each finding that may depend on a missing header says so. A rule that reads
facts headers supply (function declarations, macros and macro constants,
summaries of functions a header defines, struct layouts) and reports in a
file whose ``#include`` graph (including the build's forced includes)
reaches a header that a project file names and the scan could not find
carries the names of those headers: ``missing_headers`` in the JSON export,
``properties.missingHeaders`` in SARIF, and a ``note: may depend on header(s)
the scan could not find`` line with ``-v``. It says *may*: the rule could have
needed something those headers declare, not that it did. A finding without
the marker did not depend on any missing header, so comparing two hosts'
exports separates the findings a header explains from the ones it cannot.
A header missing only from a system header's own includes (``bits/*`` from
the C library's headers, say) marks no finding, and neither does one of the
compiler's built-in or multiarch headers above; both are in ``-v`` and
``--report-headers``.

The reverse holds too. A macro the scan took from a header outside the
project, and nowhere else, can decide what a finding sees: one library's
``#define XFREE free`` read in place of another library's own ``XFREE``. A
finding of such a rule whose line spells a macro only an outside header
defines names it and that header: ``harvested_from`` in the JSON export,
``properties.harvestedFrom`` in SARIF, and a ``note: uses macro(s) defined only
outside the project`` line with ``-v``. It goes by the finding's line, not by
what the rule used: a macro the finding relies on but that is spelled on
another line (at a declaration, or inside another macro's body) is not named,
and a macro on the line that the rule did not use is, as is a macro name that
appears on the line only inside a comment or a string.

None of this changes a finding.

Seeing Where the Engine Is Blind
--------------------------------

Everything above widens what the macro-expansion engine can see; nothing above
tells you what it still cannot. Because aurora-lint runs without a preprocessor,
the engine makes a handful of silent decisions on every scan — a variadic or
``#``/``##`` macro is skipped, a definition under ``#ifdef _WIN32`` is dropped
under the POSIX profile, the first of two ``#ifdef``-selected definitions wins,
a header on no search path is never opened, a call to a name nothing defines
stays opaque. Each is the right default; each is also a place a defect can
hide with no finding saying so. ``--report-macro-gaps`` prints them::

    aurora-lint src/ -d src/ -I include/ --report-macro-gaps
    aurora-lint src/ -d src/ -I include/ --report-macro-gaps=macro-gaps.json

The summary comes after the findings, as a per-kind count and up to 25 rows
per kind; ``=FILE`` (the ``=`` is required, so the path is never mistaken for
the scan target) writes every row as JSON with a ``kind`` from this list:

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - ``kind``
     - What it says
   * - ``variadic-definition``, ``paste-definition``, ``malformed-definition``
     - A function-like ``#define`` the collector will never expand, and why.
   * - ``assumed-dead-definition``
     - Dropped because its branch never compiles under the configuration the
       scan assumed — the POSIX profile (``_MSC_VER``, ``_WIN32``,
       ``__vxworks``, …) or a ``--compile-commands`` declaration. Noise on that
       configuration; the whole story on any other. This is the kind that
       measures how much the one profile decides.
   * - ``locally-dead-definition``
     - Dropped because the *file itself* proves the branch dead: ``#if 0``, a
       ``__cplusplus`` arm built as C, or a macro the file unconditionally
       ``#define``\ s or ``#undef``\ s above the test. No configuration would
       revive it, so this is correct behaviour rather than a blind spot.
   * - ``ambiguous-definition``
     - The same name is defined more than once in one file under conditions
       the profile cannot settle (``#ifdef WITH_TLS``). The first is used; the
       row names the others.
   * - ``conflicting-definition``
     - Defined differently in two scanned files — a project ``config.h``
       overriding a vendored library's default, say. Scan order decides which
       one every invocation gets.
   * - ``unresolved-include``
     - An ``#include`` that resolved to no file. One row per header
       project-wide; a header the ``-d`` pre-scan already walked is not
       reported even when no ``-I`` places it.
   * - ``unexpandable-invocation``
     - A call to one of the skipped definitions above: known to be a macro,
       known to be opaque.
   * - ``arity-mismatch``
     - The call's argument count differs from the definition held — usually
       the sign that a different ``#ifdef`` branch is live at this site.
   * - ``unknown-callee``
     - A call to a name no scanned file defines or declares and that is not a
       C standard-library function. ``ALL_CAPS`` names are almost certainly
       macros from an unscanned header; the rest are prototypes it never saw.

The rows are the engine's own decisions, not a second opinion, so the report
cannot disagree with the analysis it describes; and it is built from a
parse-only pass, so it adds no findings and removes none. In CI the useful
habit is to keep the JSON as a build artifact and watch the per-kind totals:
a jump in ``unknown-callee`` after a dependency bump means a header stopped
resolving, and ``conflicting-definition`` rows are worth reading once, since
each one is a name whose meaning depends on scan order.

Deallocators the Scan Cannot See
--------------------------------

A call frees its argument only where the scan can show it: ``free``, a function
whose body frees the argument (through any chain of wrappers the scan also
reads), a macro that expands to such a call, or a deallocator declared with
``--deallocator`` or ``[environment.deallocators]`` (see :doc:`configuration`).
A callee's name is never evidence: a library's ``SSL_free`` or
``curl_easy_cleanup`` has no body in the scan, so an allocation handed to it is
reported leaked by MEM31-C, and a use of it afterwards is not a use-after-free.
``--report-deallocator-candidates`` lists the callees worth declaring::

    aurora-lint src/ -d src/ --report-deallocator-candidates
    aurora-lint src/ -d src/ --report-deallocator-candidates=candidates.json

A callee is listed when it is shaped like a deallocator by name (``*_free``,
``destroy_*``, ``*_cleanup``, ``*_release``, ...), nothing in the scan shows it
freeing anything, and an allocation handed to it was reported leaked, so that
declaring it would change that finding. Each row gives the name and the
1-based argument to declare it with, how many such calls there were, and the
first one's file and line. Declare only the ones that really are deallocators:
the name is why a callee is listed, not proof of what it does. The report never
changes a finding, and it is not part of the settings, so it does not change
the settings hash either.


File Exclusion
--------------

``--exclude-all`` leaves files matching a path glob out of everything: they
are not scanned, nothing is reported in them, and the cross-file pre-scan does
not read them, so their definitions (function summaries, macro and alias
definitions, never-returning functions) do not stand for the ones the rest of
the code calls. Use it for test harnesses, example programs, checked-in
amalgamations and build tooling that aren't part of the shipped product.
Repeatable; each occurrence adds one more glob:

::

    # Drop a single generated/amalgamated file
    aurora-lint /path/to/project --exclude-all '**/onelua.c'

    # Drop a whole subtree
    aurora-lint /path/to/project --exclude-all 'tests/**' --exclude-all 'examples/**'

    # Combine multiple globs to scope down to just the shipped product
    aurora-lint /path/to/repo \
        --exclude-all 'tests/**' --exclude-all 'docs/**' --exclude-all 'scripts/**'

Globs are matched against each file's path relative to the scan root (same
semantics as a project's own ``toolchain.toml`` ``[ignore].paths``, which are
merged in automatically if present, as ``--report-exclude`` globs: nothing is
reported in them, but they are still read for cross-file facts, as they always
were). A pattern like ``tests/**``
matches anywhere a ``tests`` directory sits at that depth; use a leading
``**/`` (e.g. ``**/ltests.c``) to match a filename regardless of its
directory.

Two options leave a file out of only one half:

- ``--report-exclude`` reports nothing in matching files but still reads them
  for cross-file facts. Use it for vendored code the product links and ships:
  its definitions are the ones your calls reach, but its findings are not
  yours to fix.
- ``--prescan-exclude`` scans and reports matching files but does not read
  them for cross-file facts. Use it for stubs, fuzz harnesses and
  alternate-platform files that do not link into the product under analysis,
  whose definitions would otherwise count as another build of the functions
  the product calls.

A header in an excluded tree that a scanned file ``#include``\ s is still read
through ``-I`` include resolution: it is part of that file's translation unit.
A manifest's ``[scope]`` table takes the same three lists
(``exclude_all``, ``report_exclude``, ``prescan_exclude``) and adds to the
command line's. A prescan cache (``--save-prescan``) records which files it
was built without, and ``--load-prescan`` refuses it under a different
``--exclude-all`` or ``--prescan-exclude``.

``--exclude`` is deprecated. It keeps the meaning it has always had, which is
``--report-exclude``'s: nothing is reported in matching files, but they are
still read for cross-file facts. So an existing command line gives the same
findings as before; it also prints a one-line warning. Replace it with
``--report-exclude`` to keep that behaviour, or with ``--exclude-all`` to
leave the files out of the cross-file facts too.

.. important::

    ``--exclude-all`` and ``--report-exclude`` (and the deprecated
    ``--exclude``) are the only flags that remove files from the scan; a
    manifest's ``[scope]`` table and ``toolchain.toml``'s ``[ignore].paths``
    do the same from a file.
    ``-d``/``--directories`` does the opposite: it *adds* directories to
    pre-scan for cross-file context (function summaries, macro aliases, ...)
    and has no effect on which files are actually analyzed and reported on.
    Passing ``-d some/dir`` does **not** restrict analysis to ``some/dir`` —
    if you want a scan restricted to a subset of a larger tree, either point
    the ``PATH`` argument at that subdirectory or exclude everything else
    with ``--exclude-all``.


Export Formats
--------------

aurora-lint determines the export format from the file extension:

=============== ===============================================================
Extension       Format
=============== ===============================================================
``.json``       JSON array of violation objects
``.sarif``      `SARIF 2.1.0 <https://sarifweb.azurewebsites.net/>`_ for IDE and CI integration
``.sarif.json`` Same as ``.sarif``
=============== ===============================================================

::

    aurora-lint /path/to/repo --export results.json
    aurora-lint /path/to/repo --export results.sarif

SARIF is the full report. Each result carries its source line
(``region.snippet``), each rule its CERT description, and each scanned file its
SHA-256 (``artifacts[].hashes``), so the report stands on its own without the
scanned tree. Both formats name aurora-lint as their producer: SARIF in
``tool.driver``, JSON in a ``tool`` key on each object.

For a spreadsheet, convert the SARIF report (``.xlsx`` needs ``openpyxl``)::

    python scripts/sarif_convert.py results.sarif findings.csv
    python scripts/sarif_convert.py results.sarif findings.xlsx

Each row is one active finding (add ``--include-suppressed`` for the rest),
laid out as Title, Description, Work Item Type, State, Severity, Priority and
Tags, the layout aurora-lint's built-in CSV/XLSX export used before it was
removed.

JSON export produces an array of violation objects, each containing the keys
below. ``missing_headers`` and ``harvested_from`` (see *Headers the Scan Could
Not Find*) appear only on a finding they apply to.

.. code-block:: json

    {
        "tool": "aurora-lint",
        "file": "src/main.c",
        "line": 42,
        "column": 5,
        "rule_id": "ARR30-C",
        "severity": "High",
        "message": "Do not form or use out-of-bounds pointers or array subscripts",
        "suggestion": "Validate array index before use",
        "requires_manual_review": false
    }


Severity Filtering
------------------

Control which violations are reported and which trigger failure:

::

    # Only report Medium and above (suppress Low-severity noise)
    aurora-lint /path/to/repo --min-severity Medium

    # Fail only on High or Critical (gate CI but still report Medium)
    aurora-lint /path/to/repo --min-severity Medium --fail-on-severity High

    # Fail on any violation
    aurora-lint /path/to/repo --fail-on-violation


Rule Filtering
--------------

Restrict analysis to specific rules:

::

    # Only check memory and array rules
    aurora-lint /path/to/repo --rules MEM30-C,MEM31-C,ARR30-C,ARR32-C

    # Combine with severity and export
    aurora-lint /path/to/repo --rules STR31-C,STR32-C --min-severity High --export str-results.sarif


Diff Mode
---------

Analyze only the C files a change touches. ``PATH`` must be the root of a git
repository; any other ``PATH``, or one outside a repository, exits with code
``2``.

::

    # C files with uncommitted changes, staged or not, and untracked ones
    aurora-lint /path/to/repo --diff

    # Also the C files changed since the merge base with origin/main
    aurora-lint /path/to/repo --diff-base origin/main

``--diff`` is for a working tree. A CI checkout has no uncommitted changes, so
a pull-request job uses ``--diff-base`` with the target branch, which implies
``--diff``. The checkout needs that branch and the history back to the merge
base. The pre-scan still reads every file under ``PATH``, so cross-file
context is kept. When no C file changed, the run prints
``diff-only: no changed C files to analyze``. See :doc:`cicd-integration`.


Project-Relevance Detection
----------------------------

For a codebase with no tailored manifest, ``--detect-relevance`` scans PATH
(and any ``-d`` directories) for evidence of thread or atomic APIs
(``pthread``, ``<threads.h>``, ``_Atomic``) and Windows API usage, then
generates a manifest with the categorically-inapplicable ``WIN*`` rule class
disabled when there is no Windows API evidence. The ``CON*`` rules are never
disabled: no thread or atomic API does not mean no concurrency, since
interrupt or signal handlers are not looked for and are what share state on
bare-metal firmware. The output reports the threading finding and says so,
and the generated ``CON*`` entries carry an ``# info:`` comment when none was
found.
It never runs an analysis itself — pair it with ``--write-manifest`` to
save the generated manifest, then pass that manifest to a normal scan via
``-m``:

::

    # Generate a relevance-gated manifest for a POSIX-only codebase
    aurora-lint /path/to/repo --detect-relevance --write-manifest gated-rules.toml

    # Use it for the actual scan
    aurora-lint /path/to/repo -m gated-rules.toml

The generated manifest also carries the policy and environment settings the
run resolved: the base manifest's with any ``--profile``, ``--policy``,
``--environment``, ``--libc``, ``--include-names``, ``--data-model``,
``--set``, ``--allocator`` or ``--deallocator`` given alongside
``--detect-relevance`` layered over them, so ``-m gated-rules.toml`` scans
under the same settings without repeating the flags. A comment at the top
names the flags the values came from. Settings that combine invalidly are
refused when the manifest is written, as a scan would refuse them. What a
compile database implies (such as case-insensitive ``#include`` matching for
one written for cl) is not written; pass ``--compile-commands`` again on the
scan.

Detection is conservative by design: a rule class is disabled only when no
evidence of it was found anywhere in the scanned corpus (including
resolved ``-I``/``-d`` includes); an unresolved include path leaves the
affected rules enabled with an ``# unresolved: ...`` comment rather than
guessing. C11/Annex-K-specific rules are detected and annotated but not
yet auto-gated (v2 work); see
``docs/design/project-relevance-gating.md`` for the full design and
current scope. This is unrelated to the ``conf/realworld/*-rules.toml``
manifests used by the benchmark suite, which remain hand-curated and are
never overwritten by this flag.


Exit Codes
----------

The exit codes, what a failure costs, how it is reported (stderr and SARIF), the
``--rule-step-limit`` / ``--rule-time-limit`` budgets, the ``--max-file-size``
input guard, and what CI should do with ``3``: :doc:`error-handling`.
