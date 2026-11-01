CI/CD Integration
=================

aurora-lint is designed for CI/CD pipelines with exit codes, severity thresholds,
diff-only analysis, and SARIF output for code scanning integrations.

General Strategy
----------------

A typical CI setup uses two modes:

1. **PR analysis** (diff-only): findings in the files the pull request changed
2. **Push/merge analysis** (full scan): every file on the main branch

Both modes export SARIF for integration with code scanning dashboards.

::

    # PR mode: only the files changed since the merge base with main, fail on High+
    aurora-lint . --diff-base origin/main --min-severity Medium --fail-on-severity High --export results.sarif

    # Full scan: entire repo with cross-file context
    aurora-lint . -d . --min-severity Medium --fail-on-severity High --export results.sarif

Diff-Only Scans in CI
---------------------

There are two diff-only flags, and a CI job wants the second:

- ``--diff`` analyzes the C files with uncommitted changes, staged or not,
  and untracked ones. A CI checkout has none, so in a pull-request job
  ``--diff`` alone analyzes nothing and the job passes whatever the branch
  changed.
- ``--diff-base REF`` analyzes the C files changed between the merge base of
  ``REF`` and ``HEAD``, plus those ``--diff`` alone finds, and implies
  ``--diff``. In a pull-request job, ``REF`` is the target branch, for example
  ``origin/main``. The checkout must hold ``REF`` and the history back to the
  merge base. A shallow clone does not, and the error says so: use
  ``fetch-depth: 0`` in ``actions/checkout`` (``fetchDepth: 0`` in Azure
  Pipelines), or run ``git fetch --unshallow``.

With either flag:

- ``PATH`` must be the root of the git repository. Any other ``PATH`` (a
  subdirectory, a single file, a directory outside any repository) is refused
  with exit code ``2``. To leave parts of the repository out, pass the root
  with ``--report-exclude``, ``--exclude-all`` or ``toolchain.toml``'s
  ``[ignore]`` paths.
- Only the analysis is limited to the changed files. The pre-scan still
  reads every file under ``PATH``, so cross-file findings in a changed file
  keep their context.
- When no C file changed, the log says
  ``diff-only: no changed C files to analyze``, so it can be told apart from
  a clean scan.

GitHub Actions
--------------

An example workflow is at ``examples/aurora-lint-analysis.yml``; copy it into
your repository's ``.github/workflows/``. Its pull-request job passes
``--diff-base origin/${{ github.base_ref }}``:

.. literalinclude:: ../examples/aurora-lint-analysis.yml
   :language: yaml

Azure DevOps
-------------

An example Azure Pipelines configuration is at ``docs/azure-pipelines.yml``.
Its pull-request job passes ``--diff-base origin/main``, the branch its
``pr`` trigger targets:

.. literalinclude:: azure-pipelines.yml
   :language: yaml

Knowing What the Scan Could Not See
-----------------------------------

A clean scan of code the analyzer could not fully read is not the same as a
clean scan. aurora-lint works without a preprocessor, so heavy macro use or a
header it never found can leave parts of a tree opaque to the dataflow rules
without any finding saying so. ``--report-macro-gaps=FILE`` writes where that
happened as JSON (skipped macro definitions, unresolved ``#include``\s, calls
it could not attribute) without changing a single finding; keep the file as a
build artifact next to the SARIF, and treat a jump in its per-kind totals the
way you would treat a jump in findings::

    aurora-lint . -d . --export results.sarif --report-macro-gaps=macro-gaps.json

The kinds and what each means are in :doc:`cli-usage`.

SARIF Integration Tips
----------------------

- **GitHub Code Scanning**: Use ``github/codeql-action/upload-sarif@v3`` to
  surface aurora-lint violations as code scanning alerts on PRs and the Security tab.
- **Azure DevOps**: Publish SARIF as a build artifact. Third-party extensions
  (e.g., SARIF SAST Scans Tab) can render results inline.
- **VS Code**: Open ``.sarif`` files with the
  `SARIF Viewer <https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer>`_
  extension for inline annotations.
- **IDE Integration**: Any tool that consumes SARIF 2.1.0 can display aurora-lint results.

CI/CD Readiness
---------------

.. list-table::
   :header-rows: 1
   :widths: 25 50 10

   * - Component
     - Status
     - Readiness
   * - Output Formats
     - SARIF 2.1.0, JSON
     - 100%
   * - Exit Codes
     - ``--fail-on-violation``, ``--fail-on-severity``; ``3`` for an incomplete
       scan (:doc:`error-handling`)
     - 100%
   * - Severity Filtering
     - ``--min-severity``, ``--fail-on-severity``
     - 100%
   * - Rule Filtering
     - ``--rules ARR30-C,MEM30-C``
     - 100%
   * - Incremental
     - ``--diff`` (uncommitted changes), ``--diff-base REF`` (a branch's
       changes)
     - 90%
   * - CI Workflows
     - GitHub Actions + Azure DevOps templates
     - 100%
   * - Suppressions
     - SHA-256 code-location
     - 70%
   * - Docker
     - No image published
     - 0%

**Remaining gaps**:

1. **No baseline-aware suppression** — can't report "only new violations since
   last run"
2. **No Docker image** for containerized CI/CD
3. **Unclassified real-world violation density** — no ground truth to split TP
   vs FP on production code
