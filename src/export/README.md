# Export Module

Writes a scan's findings to a file, chosen by the `--export` path's extension.

## Formats

### SARIF 2.1.0 (`.sarif`, `.sarif.json`)

The full report, for IDEs, CI code-scanning and anything downstream:

- `tool.driver` names aurora-lint, its version and repository URL
- `tool.driver.rules[]`: each rule's CERT description and SEI wiki `helpUri`
- `results[]`: rule, level, message, location, and the flagged source line as
  `region.snippet`; `fixes` when the rule has a suggestion;
  `properties.requiresManualReview` when the rule could not decide confidently
- suppressed findings are included, each carrying an in-source `suppressions` entry
- `artifacts[]`: every file a finding points into, with its SHA-256

Because the report carries snippets, descriptions and hashes, it stands on its
own: nothing downstream needs the scanned tree or the binary.

### JSON (`.json`)

A top-level array of active violation objects (`tool`, `rule_id`, `severity`,
`message`, `file`, `line`, `column`, `suggestion`, `requires_manual_review`).
Kept as a bare array because consumers, the benchmark runners among them,
index it directly.

### Spreadsheets

Not built into the tool. `scripts/sarif_convert.py` turns a SARIF report into
CSV, or XLSX when `openpyxl` is installed.

Any other extension is an error that points at the converter, never a silent
fallback to some other format.
