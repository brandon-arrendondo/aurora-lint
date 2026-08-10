Advanced CLI Usage
==================

Full Command Reference
----------------------

::

    sqc [OPTIONS] [PATH]

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
          --suppress-file <FILE>       Path to .sqc-suppress.toml file
                                       (auto-detected in project root if not specified;
                                       supports [[suppression]] hash entries and
                                       [[wildcard]] glob/prefix entries)
      -I, --include-path <DIR>         Include search paths for resolving #include directives
                                       (repeatable; like compiler -I flag)
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
    sqc /path/to/project -d /path/to/project

    # Include additional directories (e.g., shared headers, sibling modules)
    sqc /path/to/project -d /path/to/project -d /path/to/shared/headers

    # Multiple -d flags stack — all are pre-scanned before analysis begins
    sqc src/ -d src/ -d vendor/ -d third_party/

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


File Exclusion
--------------

``--exclude`` drops files matching a path glob from the scan (and from the
precision/recall denominator), for checked-in amalgamations, vendored code,
test harnesses, or build tooling that isn't part of the shipped product.
Repeatable; each occurrence adds one more glob:

::

    # Drop a single generated/amalgamated file
    sqc /path/to/project --exclude '**/onelua.c'

    # Drop a whole subtree
    sqc /path/to/project --exclude 'tests/**' --exclude 'vendor/**'

    # Combine multiple globs to scope down to just the shipped product
    sqc /path/to/repo \
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

SqC determines the export format from the file extension:

=========== ===============================================================
Extension   Format
=========== ===============================================================
``.csv``    Comma-separated values (file, line, column, rule, severity, message)
``.xlsx``   Excel workbook with formatted columns and severity coloring
``.json``   JSON array of violation objects
``.sarif``  `SARIF 2.1.0 <https://sarifweb.azurewebsites.net/>`_ for IDE and CI integration
=========== ===============================================================

::

    sqc /path/to/repo --export results.csv
    sqc /path/to/repo --export results.xlsx
    sqc /path/to/repo --export results.json
    sqc /path/to/repo --export results.sarif

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
    sqc /path/to/repo --min-severity Medium

    # Fail only on High or Critical (gate CI but still report Medium)
    sqc /path/to/repo --min-severity Medium --fail-on-severity High

    # Strict mode: fail on any violation
    sqc /path/to/repo --fail-on-violation


Rule Filtering
--------------

Restrict analysis to specific rules:

::

    # Only check memory and array rules
    sqc /path/to/repo --rules MEM30-C,MEM31-C,ARR30-C,ARR32-C

    # Combine with severity and export
    sqc /path/to/repo --rules STR31-C,STR32-C --min-severity High --export str-results.sarif


Diff Mode
---------

Analyze only files modified in the current git working tree (staged + unstaged
changes vs HEAD):

::

    # Only analyze changed C files
    sqc /path/to/repo --diff

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
    sqc /path/to/repo --detect-relevance --write-manifest gated-rules.toml

    # Use it for the actual scan
    sqc /path/to/repo -m gated-rules.toml

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
