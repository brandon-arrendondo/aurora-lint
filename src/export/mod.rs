mod csv;
mod excel;
mod json;
mod sarif;

use super::analyze::SuppressedViolation;
use super::manifest::RuleManifest;
use super::rules::RuleViolation;
use csv::export_all_violations_to_csv;
use excel::export_all_violations_to_excel;
use json::export_all_violations_to_json;
use sarif::export_all_violations_to_sarif;

use anyhow::Result;

/// Write `violations` (and, where the format supports it, `suppressed`) to
/// `export_path`, dispatching on its extension: `.sarif.json`/`.sarif` for
/// SARIF 2.1.0, `.xlsx` for Excel, `.csv`, or `.json`.
pub fn export_all_violations(
    violations: &[RuleViolation],
    suppressed: &[SuppressedViolation],
    export_path: &str,
    _manifest: &RuleManifest,
) -> Result<()> {
    use std::path::Path;

    let path = Path::new(export_path);

    // Check for .sarif.json double extension
    if export_path.ends_with(".sarif.json") {
        return export_all_violations_to_sarif(violations, suppressed, export_path);
    }

    if let Some(extension) = path.extension() {
        match extension.to_str() {
            Some("xlsx") => export_all_violations_to_excel(violations, export_path, _manifest),
            Some("csv") => export_all_violations_to_csv(violations, export_path, _manifest),
            Some("json") => export_all_violations_to_json(violations, export_path),
            Some("sarif") => export_all_violations_to_sarif(violations, suppressed, export_path),
            _ => {
                // Default to Excel for unknown extensions
                export_all_violations_to_excel(violations, export_path, _manifest)
            }
        }
    } else {
        // No extension, default to Excel
        export_all_violations_to_excel(violations, export_path, _manifest)
    }
}
