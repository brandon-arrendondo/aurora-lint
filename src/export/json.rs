use super::TOOL_NAME;
use crate::rules::RuleViolation;

use anyhow::Result;
use std::fs::File;
use std::io::BufWriter;

/// A top-level array, kept that way because consumers (the benchmark runner
/// among them) index it directly; the producer is named per object instead of
/// in a wrapper, which would break every one of them.
pub fn export_all_violations_to_json(
    violations: &[RuleViolation],
    json_path: &str,
    headers: super::Headers<'_>,
) -> Result<()> {
    let output: Vec<serde_json::Value> = violations
        .iter()
        .map(|v| {
            let mut row = serde_json::json!({
                "tool": TOOL_NAME,
                "rule_id": v.rule_id,
                "severity": v.severity,
                "message": v.message,
                "file": v.file_path,
                "line": v.line,
                "column": v.column,
                "suggestion": v.suggestion,
                "requires_manual_review": v.needs_manual_review(),
            });
            // Present only when the finding may depend on a header the scan
            // could not find, so an export from a host with every header is
            // unchanged.
            if let Some(missing) = headers.of(v) {
                row["missing_headers"] = serde_json::json!(missing);
            }
            row
        })
        .collect();

    let file = File::create(json_path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &output)?;

    Ok(())
}
