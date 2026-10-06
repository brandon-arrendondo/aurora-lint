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

/// What did not complete in the scan an export describes (ADR-0017). SARIF
/// records it in `invocations`; the JSON array is findings only and stays
/// that way, so the exit code is what says a JSON export is incomplete.
#[derive(Debug, Default, Clone, Copy)]
pub struct Incomplete<'a> {
    /// Units of work that crashed or ran out of budget.
    pub failures: &'a [crate::analyze::containment::ScanFailure],
    /// Rules abandoned for the scan, whose findings are all withheld.
    pub abandoned_rules: &'a [String],
}

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
    incomplete: Incomplete<'_>,
) -> Result<()> {
    if export_path.ends_with(".sarif") || export_path.ends_with(".sarif.json") {
        return export_all_violations_to_sarif(
            violations,
            suppressed,
            export_path,
            settings,
            incomplete,
        );
    }
    if export_path.ends_with(".json") {
        return export_all_violations_to_json(violations, export_path);
    }
    bail!(
        "unsupported export format for '{export_path}': use .sarif (or .json); \
         for CSV/XLSX, convert the SARIF with scripts/sarif_convert.py"
    )
}
