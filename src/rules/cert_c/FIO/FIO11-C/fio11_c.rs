//! FIO11-C: Take care when specifying the mode parameter of fopen()
//!
//! This rule detects non-standard mode strings passed to fopen() and fopen_s().
//! Only the mode strings defined in the C Standard should be used for portability.
//!
//! VALID MODE STRINGS (C Standard):
//! - "r"    - Open text file for reading
//! - "w"    - Truncate to zero length or create text file for writing
//! - "wx"   - Create text file for writing (C11)
//! - "a"    - Append; open or create text file for writing at end-of-file
//! - "rb"   - Open binary file for reading
//! - "wb"   - Truncate to zero length or create binary file for writing
//! - "wbx"  - Create binary file for writing (C11)
//! - "ab"   - Append; open or create binary file for writing at end-of-file
//! - "r+"   - Open text file for update (reading and writing)
//! - "w+"   - Truncate to zero length or create text file for update
//! - "w+x"  - Create text file for update (C11)
//! - "a+"   - Append; open or create text file for update
//! - "r+b" or "rb+" - Open binary file for update
//! - "w+b" or "wb+" - Truncate or create binary file for update
//! - "w+bx" or "wb+x" - Create binary file for update (C11)
//! - "a+b" or "ab+" - Append; open or create binary file for update
//!
//! VIOLATIONS:
//! - fopen("file", "rw")    // "rw" is not a valid mode
//! - fopen("file", "wr")    // "wr" is not a valid mode
//! - fopen("file", "rwa")   // Invalid combination
//!
//! COMPLIANT:
//! - fopen("file", "r")     // Valid read mode
//! - fopen("file", "w+")    // Valid read/write mode
//! - fopen("file", "rb")    // Valid binary read mode

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio11C;

// Valid fopen mode strings per C Standard
const VALID_MODES: &[&str] = &[
    "r", "w", "a", "rb", "wb", "ab", "r+", "w+", "a+", "r+b", "rb+", "w+b", "wb+", "a+b", "ab+",
    "wx", "wbx", "w+x", "w+bx", "wb+x",
];

impl CertRule for Fio11C {
    fn rule_id(&self) -> &'static str {
        "FIO11-C"
    }

    fn description(&self) -> &'static str {
        "Take care when specifying the mode parameter of fopen()"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "FIO11-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Fio11C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if func_name == "fopen" || func_name == "fopen_s" {
                    self.check_fopen_call(&call, source, violations);
                }
            }
        }
    }

    fn check_fopen_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            // fopen(filename, mode) - mode is the 2nd argument
            // fopen_s(pFile, filename, mode) - mode is the 3rd argument
            let mode_arg_index = {
                if let Some(function) = node.child_by_field_name("function") {
                    let func_name = get_node_text(&function, source);
                    if func_name == "fopen_s" {
                        2 // 3rd argument (0-indexed)
                    } else {
                        1 // 2nd argument (0-indexed)
                    }
                } else {
                    1
                }
            };

            let args = self.extract_arguments(&arguments);

            if args.len() > mode_arg_index {
                let mode_node = &args[mode_arg_index];
                let mode_text = get_node_text(mode_node, source);

                // Check if it's a string literal
                if mode_node.kind() == "string_literal" {
                    // Remove quotes from the mode string
                    let mode = mode_text.trim_matches('"');

                    if !self.is_valid_mode(mode) {
                        let start_point = mode_node.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Non-standard fopen() mode string '{}'; use only C standard mode strings for portability",
                                mode
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Use one of: r, w, a, rb, wb, ab, r+, w+, a+, r+b, rb+, w+b, wb+, a+b, ab+, wx, wbx, w+x, w+bx, wb+x".to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    fn extract_arguments<'a>(&self, arguments_node: &Node<'a>) -> Vec<Node<'a>> {
        let mut args = Vec::new();

        for i in 0..arguments_node.child_count() {
            if let Some(child) = arguments_node.child(i) {
                // Skip commas and parentheses
                if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                    args.push(child);
                }
            }
        }

        args
    }

    fn is_valid_mode(&self, mode: &str) -> bool {
        VALID_MODES.contains(&mode)
    }
}
