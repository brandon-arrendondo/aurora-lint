use crate::analyze::SuppressedViolation;
use crate::manifest::Severity;
use crate::rules::RuleViolation;

use anyhow::Result;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufWriter;

fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn violation_to_sarif_result(
    v: &RuleViolation,
    rule_index: &BTreeMap<&str, usize>,
) -> serde_json::Value {
    let idx = rule_index.get(v.rule_id.as_str()).copied().unwrap_or(0);
    let mut result = serde_json::json!({
        "ruleId": v.rule_id,
        "ruleIndex": idx,
        "level": severity_to_sarif_level(&v.severity),
        "message": {
            "text": v.message
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": v.file_path
                },
                "region": {
                    "startLine": v.line,
                    "startColumn": v.column
                }
            }
        }]
    });
    if let Some(suggestion) = &v.suggestion {
        result["fixes"] = serde_json::json!([{
            "description": {
                "text": suggestion
            }
        }]);
    }
    if v.needs_manual_review() {
        // SARIF's own extension point for tool-defined metadata that
        // doesn't fit the fixed schema -- there's no first-class "this
        // rule couldn't confidently decide" field, so a consuming SARIF
        // viewer sees this in properties rather than losing the signal
        // entirely (the CLI's own "severity?" marker is stdout-only).
        result["properties"] = serde_json::json!({
            "requiresManualReview": true
        });
    }
    result
}

pub fn export_all_violations_to_sarif(
    violations: &[RuleViolation],
    suppressed: &[SuppressedViolation],
    sarif_path: &str,
) -> Result<()> {
    // Collect unique rules from both active and suppressed violations
    let mut rules_map: BTreeMap<String, &RuleViolation> = BTreeMap::new();
    for v in violations {
        rules_map.entry(v.rule_id.clone()).or_insert(v);
    }
    for s in suppressed {
        rules_map
            .entry(s.violation.rule_id.clone())
            .or_insert(&s.violation);
    }

    // Build rule index for result references
    let rule_index: BTreeMap<&str, usize> = rules_map
        .keys()
        .enumerate()
        .map(|(i, k)| (k.as_str(), i))
        .collect();

    let rules_array: Vec<serde_json::Value> = rules_map
        .iter()
        .map(|(rule_id, v)| {
            serde_json::json!({
                "id": rule_id,
                "shortDescription": {
                    "text": v.message
                },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(&v.severity)
                },
                "helpUri": format!("https://wiki.sei.cmu.edu/confluence/display/c/{}", rule_id)
            })
        })
        .collect();

    // Build results: active violations
    let mut results_array: Vec<serde_json::Value> = violations
        .iter()
        .map(|v| violation_to_sarif_result(v, &rule_index))
        .collect();

    // Append suppressed violations with SARIF suppressions array
    for s in suppressed {
        let mut result = violation_to_sarif_result(&s.violation, &rule_index);
        result["suppressions"] = serde_json::json!([{
            "kind": "inSource",
            "justification": s.justification
        }]);
        results_array.push(result);
    }

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "aurora-lint",
                    "version": env!("CARGO_PKG_VERSION"),
                    // From Cargo.toml's `repository`, so a repo rename cannot leave a
                    // stale URL here (it was a `your-org/sqc` placeholder before).
                    "informationUri": env!("CARGO_PKG_REPOSITORY"),
                    "rules": rules_array
                }
            },
            "results": results_array
        }]
    });

    let file = File::create(sarif_path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &sarif)?;

    Ok(())
}
