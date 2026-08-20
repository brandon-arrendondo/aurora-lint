use crate::rules::RuleViolation;

use anyhow::Result;
use std::fs::File;
use std::io::BufWriter;

pub fn export_all_violations_to_json(violations: &[RuleViolation], json_path: &str) -> Result<()> {
    let output: Vec<serde_json::Value> = violations
        .iter()
        .map(|v| {
            serde_json::json!({
                "rule_id": v.rule_id,
                "severity": v.severity,
                "message": v.message,
                "file": v.file_path,
                "line": v.line,
                "column": v.column,
                "suggestion": v.suggestion,
                "requires_manual_review": v.needs_manual_review(),
            })
        })
        .collect();

    let file = File::create(json_path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &output)?;

    Ok(())
}
