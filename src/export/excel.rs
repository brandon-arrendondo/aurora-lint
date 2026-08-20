use crate::analyze::get_code_snippet;
use crate::prelude::*;
use crate::rules::get_rule_description;

pub fn export_all_violations_to_excel(
    violations: &[RuleViolation],
    excel_path: &str,
    _manifest: &RuleManifest,
) -> Result<()> {
    use rust_xlsxwriter::{Color as XlsxColor, Format, Workbook};

    let registry = RuleRegistry::new();
    let mut workbook = Workbook::new();
    let worksheet = workbook.add_worksheet();

    // Create header format
    let header_format = Format::new()
        .set_bold()
        .set_background_color(XlsxColor::RGB(0xD9D9D9));

    // Write headers
    let headers = [
        "Title",
        "Description",
        "Work Item Type",
        "State",
        "Severity",
        "Priority",
    ];

    for (col, header) in headers.iter().enumerate() {
        worksheet.write_string_with_format(0, col as u16, *header, &header_format)?;
    }

    // Write all violations
    for (row, violation) in (1u32..).zip(violations.iter()) {
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

        worksheet.write_string(row, 0, &title)?;
        worksheet.write_string(row, 1, &description)?;
        worksheet.write_string(row, 2, "Bug")?;
        worksheet.write_string(row, 3, "Proposed")?;
        worksheet.write_string(row, 4, "1 - Critical")?;
        worksheet.write_string(row, 5, "1")?;
    }

    // Auto-fit columns
    worksheet.autofit();

    workbook.save(excel_path)?;
    Ok(())
}
