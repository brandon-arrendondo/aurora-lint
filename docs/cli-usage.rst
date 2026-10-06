Advanced CLI Usage
==================

Full Command Reference
----------------------

::

    aurora-lint [OPTIONS] [PATH]

    Arguments:
      [PATH]  Path to the file, directory, or git repository to analyze [default: .]

    Options:
      -m, --manifest <FILE>            Path to the rules manifest file
                                       [default: rules_templates/rules-all.toml]
      -i, --interactive                Run in interactive terminal UI mode
                                       (requires building with `--features tui`)
      -e, --export <FILE>              Export violations to file (format by extension:
                                       .sarif, .sarif.json, .json)
          --generate-suppression <FILE:LINE:RULE>
                                       Generate suppression entry for a specific violation
      -d, --directories <DIR>          Additional directories to pre-scan for function
                                       definitions (repeatable; enables cross-file context)
          --fail-on-violation          Exit with code 1 if any violations are found
          --fail-on-severity <LEVEL>   Exit with code 1 if any violation meets or exceeds
                                       this severity [Low, Medium, High, Critical]
          --min-severity <LEVEL>       Only report violations at or above this severity
                                       [Low, Medium, High, Critical]
          --rules <RULE1,RULE2,...>    Only report violations from these rules (comma-separated)
          --exclude-all <GLOB>         Leave files matching this path glob out of
                                       everything: not scanned, not reported, and not
                                       read for cross-file facts (repeatable, e.g.
                                       --exclude-all '**/onelua.c' --exclude-all 'testes/**')
          --exclude <GLOB>             Deprecated: same as --report-exclude
          --report-exclude <GLOB>      Report nothing in matching files, but still read
                                       them for cross-file facts (repeatable)
          --prescan-exclude <GLOB>     Scan and report matching files, but do not read
                                       them for cross-file facts (repeatable)
          --diff                       Only analyze modified/new C files (requires git repo)
          --suppress-file <FILE>       Path to suppress.toml file
                                       (auto-detected in project root if not specified;
                                       [[suppress]] entries, matched by hash or by
                                       glob/prefix)
      -I, --include-path <DIR>         Include search paths for resolving #include directives
                                       (repeatable; like compiler -I flag)
          --compile-commands <FILE>    Read include search paths and -D macros from a
                                       compile_commands.json (optional; improves cross-file
                                       macro/header coverage for projects that already have
                                       a compile database)
          --system-includes            Also search the compiler's own built-in system header
                                       directories, found by asking it (cc -E -Wp,-v -).
                                       Off by default: it spawns a compiler. Usable with or
                                       without --compile-commands, which can never contain
                                       these paths
          --report-macro-gaps[=FILE]   After the scan, report where the macro-expansion
                                       engine was blind: definitions it skipped, #includes
                                       it could not resolve, calls it could not attribute.
                                       Summary on stdout; =FILE also writes every row as
                                       JSON. Never changes a finding
          --report-deallocator-candidates[=FILE]
                                       After the scan, list callees shaped like
                                       deallocators by name that nothing shows freeing,
                                       where an allocation handed to one was reported
                                       leaked. Summary on stdout; =FILE also writes every
                                       row as JSON. Never changes a finding
      -v, --verbose                    Increase output verbosity (repeat for more detail;
                                       -v shows per-rule scanning progress)
          --save-prescan <FILE>        Save prescan context to a binary cache file
                                       (speeds up repeated scans of the same project)
          --load-prescan <FILE>        Load prescan context from cache instead of
                                       re-scanning -d directories
      -j, --jobs <N>                   Number of parallel analysis threads
                                       (0 = auto-detect, 1 = sequential; default: 0)
          --profile <PRESET>           Preset for both settings axes: default (default
                                       policy, hosted) or strict (strict policy,
                                       freestanding). Overrides the manifest's `profile`
          --policy <POLICY>            Policy axis: which findings are reported
                                       [default, strict] (overrides the preset)
          --environment <KIND>         Environment axis [hosted, freestanding] (overrides
                                       the preset). Declared, never inferred from the
                                       scanning host
          --libc <MODEL>               C library model whose documented contracts are
                                       trusted [iso-posix, glibc, musl, newlib,
                                       picolibc, custom]
          --data-model <MODEL>         Data model: the bundle of integer facts the code is built for
                                       [iso, ilp32, lp64, llp64]. The default, iso,
                                       loads nothing, so only the widths ISO C
                                       guarantees are credited and limit macros such as
                                       INT_MAX are unknown. Same as
                                       ``[environment] data_model``, which a
                                       ``--profile`` keeps. Override one fact with
                                       ``--set int_bits=16`` (also char_bits,
                                       short_bits, long_bits, long_long_bits,
                                       pointer_bits, wchar_t_bits, char_signed,
                                       float_bytes, double_bytes, long_double_bytes,
                                       time_t_bytes, off_t_bytes). See
                                       :doc:`configuration`
          --allocator <NAME[=CONTRACT]>
                                       Declare a function the scan cannot see into as an
                                       allocator following the named standard allocator's
                                       contract [malloc, calloc, realloc, aligned_alloc,
                                       strdup, strndup; default malloc]. Repeatable; same
                                       as [environment.allocators] in the manifest
          --deallocator <NAME[=ARG]>   Declare a function the scan cannot see into as
                                       freeing its ARG-th argument (default 1).
                                       Repeatable; same as [environment.deallocators] in
                                       the manifest
          --set <NAME=VALUE>           Override one named option (repeatable); see
                                       --list-options
          --list-options [<FORMAT>]    List every policy and environment option with its
                                       value under each preset and the current settings,
                                       and every integer fact with its source (cli,
                                       config, data-model:NAME, iso-floor, unknown), then
                                       exit [text, json, rst]
          --list-rules [<FORMAT>]      List every rule the tool ships and whether the
                                       configuration enables it, then the rules it no
                                       longer ships and why, then exit [text, json]
          --check-config               Resolve the settings from the manifest and the
                                       command line exactly as a scan would, validate
                                       them, and exit without scanning: "configuration
                                       ok" and status 0, or status 1 and one error per
                                       problem
          --write-config <FILE>        Write a complete, commented configuration for the
                                       current settings (the manifest, --data-model and
                                       --set applied) and exit; a key at its default is
                                       commented out. Refuses to replace an existing FILE
                                       unless --overwrite is given; "-" writes to stdout
          --overwrite                  With --write-config: replace FILE if it exists
          --detect-relevance           Detect categorically-inapplicable rule classes
                                       (CON*/WIN*) in PATH and -d directories, then write
                                       a relevance-gated manifest with --write-manifest.
                                       Does not run an analysis.
          --write-manifest <FILE>      With --detect-relevance: write the generated
                                       manifest here (requires --detect-relevance)
      -h, --help                       Print help
      -V, --version                    Print version


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
database (they are implicit), so headers found only in ``/usr/include`` remain
out of reach.

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

=========== ===============================================================
Extension   Format
=========== ===============================================================
``.json``   JSON array of violation objects
``.sarif``  `SARIF 2.1.0 <https://sarifweb.azurewebsites.net/>`_ for IDE and CI integration
=========== ===============================================================

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

JSON export produces an array of violation objects, each containing:

.. code-block:: json

    {
        "tool": "aurora-lint",
        "file": "src/main.c",
        "line": 42,
        "column": 5,
        "rule_id": "ARR30-C",
        "severity": "High",
        "message": "Do not form or use out-of-bounds pointers or array subscripts",
        "suggestion": "Validate array index before use"
    }


Severity Filtering
------------------

Control which violations are reported and which trigger failure:

::

    # Only report Medium and above (suppress Low-severity noise)
    aurora-lint /path/to/repo --min-severity Medium

    # Fail only on High or Critical (gate CI but still report Medium)
    aurora-lint /path/to/repo --min-severity Medium --fail-on-severity High

    # Strict mode: fail on any violation
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

Analyze only files modified in the current git working tree (staged + unstaged
changes vs HEAD):

::

    # Only analyze changed C files
    aurora-lint /path/to/repo --diff

This is particularly useful in CI pipelines to provide fast feedback on pull
requests without scanning the entire codebase.


Project-Relevance Detection
----------------------------

For a codebase with no tailored manifest, ``--detect-relevance`` scans PATH
(and any ``-d`` directories) for evidence of threading (``pthread``,
``<threads.h>``, ``_Atomic``) and Windows API usage, then generates a
manifest with the categorically-inapplicable rule classes disabled
(``CON*`` if no threading evidence, ``WIN*`` if no Windows API evidence).
It never runs an analysis itself — pair it with ``--write-manifest`` to
save the generated manifest, then pass that manifest to a normal scan via
``-m``:

::

    # Generate a relevance-gated manifest for a POSIX-only codebase
    aurora-lint /path/to/repo --detect-relevance --write-manifest gated-rules.toml

    # Use it for the actual scan
    aurora-lint /path/to/repo -m gated-rules.toml

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

======  ==========================================================================
Code    Meaning
======  ==========================================================================
``0``   Success (no violations, or none meeting the failure threshold)
``1``   Violations found (when ``--fail-on-violation`` or ``--fail-on-severity`` is set)
``2``   The scan could not run (invalid path, bad manifest, invalid suppression file)
``3``   The scan is incomplete: a rule or file crashed or ran out of its budget.
        Takes precedence over ``1``, with or without ``--fail-on-*``.
======  ==========================================================================

What a failure costs, how it is reported (stderr and SARIF), the
``--rule-step-limit`` / ``--rule-time-limit`` budgets, the ``--max-file-size``
input guard, and what CI should do with ``3``: :doc:`error-handling`.
