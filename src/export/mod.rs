mod json;
mod sarif;

use super::analyze::SuppressedViolation;
use super::rules::RuleViolation;
use super::settings::AnalysisSettings;
use json::export_all_violations_to_json;
pub use sarif::export_all_violations_to_sarif;

use anyhow::{bail, Result};

/// Name every export format identifies its producer by. Stated overtly in
/// each format's own metadata slot (SARIF `tool.driver`, a JSON `tool` key)
/// so a report says what made it wherever it travels.
pub(crate) const TOOL_NAME: &str = "aurora-lint";

/// Write `violations` (and, for SARIF, `suppressed`) to `export_path`,
/// dispatching on its extension: `.sarif`/`.sarif.json` for SARIF 2.1.0, or
/// `.json` for a plain array of violation objects.
///
/// SARIF is the one full-fidelity report. Spreadsheet formats are derived
/// from it outside the tool by `scripts/sarif_convert.py`.
pub fn export_all_violations(
    violations: &[RuleViolation],
    suppressed: &[SuppressedViolation],
    export_path: &str,
    settings: &AnalysisSettings,
) -> Result<()> {
    if export_path.ends_with(".sarif") || export_path.ends_with(".sarif.json") {
        return export_all_violations_to_sarif(violations, suppressed, export_path, settings);
    }
    if export_path.ends_with(".json") {
        return export_all_violations_to_json(violations, export_path);
    }
    bail!(
        "unsupported export format for '{export_path}': use .sarif (or .json); \
         for CSV/XLSX, convert the SARIF with scripts/sarif_convert.py"
    )
}
