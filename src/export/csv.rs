pub use crate::analyze::get_code_snippet;
use crate::prelude::*;
use crate::rules::{get_rule_description, RuleRegistry, RuleViolation};

pub fn export_all_violations_to_csv(
    violations: &[RuleViolation],
    csv_path: &str,
    _manifest: &RuleManifest,
) -> Result<()> {
    use csv::Writer;

    let registry = RuleRegistry::new();
    let mut writer = Writer::from_path(csv_path)?;

    // Write CSV headers
    writer.write_record([
        "Title",
        "Description",
        "Work Item Type",
        "State",
        "Severity",
        "Priority",
    ])?;

    // Write all violations
    for violation in violations {
        let file_hash = calculate_file_hash(&violation.file_path)?;

        let review_marker = if violation.needs_manual_review() {
            "[NEEDS MANUAL REVIEW] "
        } else {
            ""
        };
        let title = format!(
            "{}{}:{}:{} version:{}",
            review_marker, violation.rule_id, violation.file_path, violation.line, file_hash
        );

        let code_snippet = get_code_snippet(&violation.file_path, violation.line)?;
        let rule_description = get_rule_description(&registry, &violation.rule_id);
        let review_note = if violation.needs_manual_review() {
            " (sqc could not confidently determine this is a violation -- review before acting.)"
        } else {
            ""
        };
        let description = format!(
            "{} - {}: {}{}",
            violation.rule_id, rule_description, code_snippet, review_note
        );

        writer.write_record([&title, &description, "Bug", "Proposed", "1 - Critical", "1"])?;
    }

    writer.flush()?;
    Ok(())
}
