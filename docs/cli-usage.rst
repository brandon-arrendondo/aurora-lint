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
                                       .csv, .xlsx, .json, .sarif, .sarif.json)
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
          --exclude <GLOB>             Exclude files matching this path glob from analysis
                                       (repeatable, e.g. --exclude '**/onelua.c'
                                       --exclude 'testes/**')
          --diff                       Only analyze modified/new C files (requires git repo)
          --suppress-file <FILE>       Path to suppress.toml file
                                       (auto-detected in project root if not specified;
                                       supports [[suppression]] hash entries and
                                       [[wildcard]] glob/prefix entries)
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
      -v, --verbose                    Increase output verbosity (repeat for more detail;
                                       -v shows per-rule scanning progress)
          --save-prescan <FILE>        Save prescan context to a binary cache file
                                       (speeds up repeated scans of the same project)
          --load-prescan <FILE>        Load prescan context from cache instead of
                                       re-scanning -d directories
      -j, --jobs <N>                   Number of parallel analysis threads
                                       (0 = auto-detect, 1 = sequential; default: 0)
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

The ``-d`` / ``--directories`` flag enables cross-file context by pre-scanning
directories for function definitions, type declarations, and macro aliases. This
significantly reduces false positives from rules like DCL31-C (unused identifiers)
and DCL07-C (type mismatches) that would otherwise flag externally-defined symbols.

::

    # Pre-scan the project directory for cross-file context
    aurora-lint /path/to/project -d /path/to/project

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

aurora-lint does **not** run a preprocessor. It reads two things out of the database and
feeds them to the pre-scan that already exists:

- **Include search paths** (``-I``, ``-isystem``, ``-iquote``, ``-idirafter``,
  resolved against each entry's ``directory``) are appended to any explicit
  ``-I`` you passed. This lets ``#include`` resolution reach headers the
  sibling-header scan would never find — notably angle-bracket includes of
  vendored or out-of-tree headers — so their macros, prototypes and struct
  types join the cross-file context.
- **Command-line macros** (``-D``, minus anything ``-U``'d) are parsed as real
  ``#define`` directives, so command-line constants fold and function-like
  ``-D`` macros become expandable exactly like ones written in a header.

Because the parse tree is untouched, every finding keeps the source location it
always had, and the ``PRE*`` rules still audit macros as written.

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


File Exclusion
--------------

``--exclude`` drops files matching a path glob from the scan (and from the
precision/recall denominator), for checked-in amalgamations, vendored code,
test harnesses, or build tooling that isn't part of the shipped product.
Repeatable; each occurrence adds one more glob:

::

    # Drop a single generated/amalgamated file
    aurora-lint /path/to/project --exclude '**/onelua.c'

    # Drop a whole subtree
    aurora-lint /path/to/project --exclude 'tests/**' --exclude 'vendor/**'

    # Combine multiple globs to scope down to just the shipped product
    aurora-lint /path/to/repo \
        --exclude 'tests/**' --exclude 'docs/**' --exclude 'scripts/**'

Globs are matched against each file's path relative to the scan root (same
semantics as a project's own ``toolchain.toml`` ``[ignore].paths``, which are
merged in automatically if present — ``--exclude`` only needs to name
patterns that aren't already covered there). A pattern like ``tests/**``
matches anywhere a ``tests`` directory sits at that depth; use a leading
``**/`` (e.g. ``**/ltests.c``) to match a filename regardless of its
directory.

.. important::

    ``--exclude`` is the only flag that removes files from the scan.
    ``-d``/``--directories`` does the opposite: it *adds* directories to
    pre-scan for cross-file context (function summaries, macro aliases, ...)
    and has no effect on which files are actually analyzed and reported on.
    Passing ``-d some/dir`` does **not** restrict analysis to ``some/dir`` —
    if you want a scan restricted to a subset of a larger tree, either point
    the ``PATH`` argument at that subdirectory or exclude everything else
    with ``--exclude``.


Export Formats
--------------

aurora-lint determines the export format from the file extension:

=========== ===============================================================
Extension   Format
=========== ===============================================================
``.csv``    Comma-separated values (file, line, column, rule, severity, message)
``.xlsx``   Excel workbook with formatted columns and severity coloring
``.json``   JSON array of violation objects
``.sarif``  `SARIF 2.1.0 <https://sarifweb.azurewebsites.net/>`_ for IDE and CI integration
=========== ===============================================================

::

    aurora-lint /path/to/repo --export results.csv
    aurora-lint /path/to/repo --export results.xlsx
    aurora-lint /path/to/repo --export results.json
    aurora-lint /path/to/repo --export results.sarif

JSON export produces an array of violation objects, each containing:

.. code-block:: json

    {
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
``2``   Analysis error (invalid path, bad manifest, parse failure)
======  ==========================================================================
