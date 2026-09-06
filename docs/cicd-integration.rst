CI/CD Integration
=================

aurora-lint is designed for CI/CD pipelines with exit codes, severity thresholds,
diff-only analysis, and SARIF output for code scanning integrations.

General Strategy
----------------

A typical CI setup uses two modes:

1. **PR analysis** (diff-only): fast feedback on changed files only
2. **Push/merge analysis** (full scan): comprehensive scan on the main branch

Both modes export SARIF for integration with code scanning dashboards.

::

    # PR mode: fast, only changed files, fail on High+
    aurora-lint . --diff --min-severity Medium --fail-on-severity High --export results.sarif

    # Full scan: entire repo with cross-file context
    aurora-lint . -d . --min-severity Medium --fail-on-severity High --export results.sarif

GitHub Actions
--------------

The repository includes a ready-to-use workflow at
``.github/workflows/aurora-lint-analysis.yml``:

.. code-block:: yaml

    name: aurora-lint CERT C Analysis

    on:
      push:
        branches: [main]
      pull_request:
        branches: [main]

    jobs:
      build:
        name: Build aurora-lint
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4

          - name: Cache Cargo
            uses: actions/cache@v4
            with:
              path: |
                ~/.cargo/registry
                ~/.cargo/git
                target
              key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

          - name: Build aurora-lint
            run: cargo build --release

          - name: Upload binary
            uses: actions/upload-artifact@v4
            with:
              name: aurora-lint-binary
              path: target/release/aurora-lint

      analyze-pr:
        name: Analyze PR (diff only)
        if: github.event_name == 'pull_request'
        needs: build
        runs-on: ubuntu-latest
        permissions:
          security-events: write
        steps:
          - uses: actions/checkout@v4
            with:
              fetch-depth: 0  # Full history for --diff mode

          - name: Download aurora-lint
            uses: actions/download-artifact@v4
            with:
              name: aurora-lint-binary

          - run: chmod +x aurora-lint

          - name: Run aurora-lint (diff mode)
            run: |
              ./aurora-lint . --diff \
                --min-severity Medium \
                --fail-on-severity High \
                --export results.sarif

          - name: Upload SARIF
            uses: github/codeql-action/upload-sarif@v3
            if: always()
            with:
              sarif_file: results.sarif

      analyze-full:
        name: Full Analysis
        if: github.event_name == 'push'
        needs: build
        runs-on: ubuntu-latest
        permissions:
          security-events: write
        steps:
          - uses: actions/checkout@v4

          - name: Download aurora-lint
            uses: actions/download-artifact@v4
            with:
              name: aurora-lint-binary

          - run: chmod +x aurora-lint

          - name: Run aurora-lint (full scan)
            run: |
              ./aurora-lint . -d . \
                --min-severity Medium \
                --fail-on-severity High \
                --export results.sarif

          - name: Upload SARIF
            uses: github/codeql-action/upload-sarif@v3
            if: always()
            with:
              sarif_file: results.sarif

Azure DevOps
-------------

A ready-to-use Azure Pipelines configuration is provided at
``docs/azure-pipelines.yml``:

.. literalinclude:: azure-pipelines.yml
   :language: yaml

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
     - CSV, XLSX, JSON, SARIF 2.1.0
     - 100%
   * - Exit Codes
     - ``--fail-on-violation``, ``--fail-on-severity``
     - 100%
   * - Severity Filtering
     - ``--min-severity``, ``--fail-on-severity``
     - 100%
   * - Rule Filtering
     - ``--rules ARR30-C,MEM30-C``
     - 100%
   * - Incremental
     - ``--diff`` (git modified files)
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
