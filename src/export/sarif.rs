use crate::analyze::SuppressedViolation;
use crate::manifest::Severity;
use crate::rules::{get_rule_description, RuleRegistry, RuleViolation};
use crate::utility::hash::sha256_hex;

use anyhow::Result;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::BufWriter;

/// One scanned file as the report records it: its position in the SARIF
/// `artifacts` array, and its lines for `region.snippet` (`None` when the
/// file could not be read at export time -- the finding still exports, just
/// without a snippet or hash).
struct ArtifactInfo {
    index: usize,
    lines: Option<Vec<String>>,
}

/// Read every file a finding points into once, in first-seen order, and
/// build both the `artifacts` array (with content hashes, so a report pins
/// the exact file version it describes) and the per-file lookup results use.
fn collect_artifacts<'a>(
    findings: impl Iterator<Item = &'a RuleViolation>,
) -> (BTreeMap<&'a str, ArtifactInfo>, Vec<serde_json::Value>) {
    let mut infos: BTreeMap<&str, ArtifactInfo> = BTreeMap::new();
    let mut artifacts = Vec::new();
    for v in findings {
        if infos.contains_key(v.file_path.as_str()) {
            continue;
        }
        let content = fs::read(&v.file_path).ok();
        let mut artifact = serde_json::json!({ "location": { "uri": v.file_path } });
        if let Some(bytes) = &content {
            artifact["hashes"] = serde_json::json!({ "sha-256": sha256_hex(bytes) });
        }
        let lines = content.map(|bytes| {
            String::from_utf8_lossy(&bytes)
                .lines()
                .map(str::to_string)
                .collect()
        });
        infos.insert(
            &v.file_path,
            ArtifactInfo {
                index: artifacts.len(),
                lines,
            },
        );
        artifacts.push(artifact);
    }
    (infos, artifacts)
}

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
    artifacts: &BTreeMap<&str, ArtifactInfo>,
) -> serde_json::Value {
    let idx = rule_index.get(v.rule_id.as_str()).copied().unwrap_or(0);
    let artifact = artifacts.get(v.file_path.as_str());
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
                    "uri": v.file_path,
                    "index": artifact.map(|a| a.index)
                },
                "region": {
                    "startLine": v.line,
                    "startColumn": v.column
                }
            }
        }]
    });
    let snippet = artifact
        .and_then(|a| a.lines.as_ref())
        .and_then(|lines| lines.get(v.line.checked_sub(1)?));
    if let Some(line) = snippet {
        result["locations"][0]["physicalLocation"]["region"]["snippet"] =
            serde_json::json!({ "text": line.trim() });
    }
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

/// Write a SARIF 2.1.0 report: active `violations` as plain results and
/// `suppressed` ones carrying an in-source `suppressions` entry. Each result
/// holds its source line as `region.snippet`, and each file its SHA-256 in
/// `artifacts`, so the report stands on its own without the scanned tree.
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

    // The rule's own description, not a finding's message: viewers show
    // shortDescription as the rule's title for every result under it.
    let registry = RuleRegistry::new();
    let rules_array: Vec<serde_json::Value> = rules_map
        .iter()
        .map(|(rule_id, v)| {
            serde_json::json!({
                "id": rule_id,
                "shortDescription": {
                    "text": get_rule_description(&registry, rule_id)
                },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(&v.severity)
                },
                "helpUri": format!("https://wiki.sei.cmu.edu/confluence/display/c/{}", rule_id)
            })
        })
        .collect();

    let (artifact_infos, artifacts_array) = collect_artifacts(
        violations
            .iter()
            .chain(suppressed.iter().map(|s| &s.violation)),
    );

    // Build results: active violations
    let mut results_array: Vec<serde_json::Value> = violations
        .iter()
        .map(|v| violation_to_sarif_result(v, &rule_index, &artifact_infos))
        .collect();

    // Append suppressed violations with SARIF suppressions array
    for s in suppressed {
        let mut result = violation_to_sarif_result(&s.violation, &rule_index, &artifact_infos);
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
                    "name": super::TOOL_NAME,
                    "version": env!("CARGO_PKG_VERSION"),
                    // From Cargo.toml's `repository`, so a repo rename cannot leave a
                    // stale URL here (it was a `your-org/sqc` placeholder before).
                    "informationUri": env!("CARGO_PKG_REPOSITORY"),
                    "rules": rules_array
                }
            },
            "artifacts": artifacts_array,
            "results": results_array
        }]
    });

    let file = File::create(sarif_path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &sarif)?;

    Ok(())
}
