// CERT C Rule: DCL08-C
// Properly encode relationships in constant definitions
//
// This rule checks that:
// 1. When constants have mathematical relationships, they should be encoded
//   (e.g., OUT_STR_LEN = IN_STR_LEN + 2 instead of separate literals)
// 2. Constants should not encode false or impermanent relationships

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Dcl08C;

impl CertRule for Dcl08C {
    fn rule_id(&self) -> &'static str {
        "DCL08-C"
    }

    fn description(&self) -> &'static str {
        "Properly encode relationships in constant definitions"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL08-C"
    }

    fn check(&self, root_node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: collect all enum constants across the entire file
        let mut all_enum_constants = std::collections::HashMap::new();
        self.collect_all_enum_constants(root_node, source, &mut all_enum_constants);

        // Second pass: check each enum for violations
        for enum_node in query::find_descendants_of_kind(*root_node, "enum_specifier") {
            self.check_enum_specifier(&enum_node, source, &mut violations, &all_enum_constants);
        }

        violations
    }
}

impl Dcl08C {
    /// Collect all enum constant names across the entire file
    fn collect_all_enum_constants(
        &self,
        node: &Node,
        source: &str,
        constants: &mut std::collections::HashMap<String, usize>,
    ) {
        for enum_node in query::find_descendants_of_kind(*node, "enum_specifier") {
            let Some(body) = enum_node.child_by_field_name("body") else {
                continue;
            };
            for enumerator in query::find_descendants_of_kind(body, "enumerator") {
                if let Some(name_node) = enumerator.child_by_field_name("name") {
                    let name = get_node_text(&name_node, source);
                    let line = name_node.start_position().row + 1;
                    constants.insert(name.to_string(), line);
                }
            }
        }
    }

    fn check_enum_specifier(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        all_constants: &std::collections::HashMap<String, usize>,
    ) {
        // Get the enum body
        let body = match node.child_by_field_name("body") {
            Some(b) => b,
            None => return,
        };

        // Collect all enumerator definitions
        let enumerators = query::find_descendants_of_kind(body, "enumerator");

        // Need at least 1 enumerator to check
        if enumerators.is_empty() {
            return;
        }

        // Check for potential missing relationships (same enum, literal values only)
        self.check_missing_relationships(&enumerators, source, violations, all_constants);
    }

    fn check_missing_relationships(
        &self,
        enumerators: &[Node],
        source: &str,
        violations: &mut Vec<RuleViolation>,
        all_constants: &std::collections::HashMap<String, usize>,
    ) {
        // Collect enumerator info for THIS enum: name and value (if literal)
        let mut enum_values = Vec::new();
        let mut this_enum_names = std::collections::HashSet::new();

        for enumerator in enumerators {
            if let Some(name_node) = enumerator.child_by_field_name("name") {
                let name = get_node_text(&name_node, source);
                this_enum_names.insert(name.to_string());

                // Check if there's a value
                if let Some(value_node) = enumerator.child_by_field_name("value") {
                    let value_text = get_node_text(&value_node, source);

                    // Check if it's a simple numeric literal
                    if let Ok(value) = value_text.parse::<i64>() {
                        enum_values.push((name, value, name_node.start_position()));
                    } else if value_text.contains('+') || value_text.contains('-') {
                        // This is a reference with arithmetic
                        // Check if it references a constant from THIS enum (that's OK)
                        // or a constant from a DIFFERENT scope (that's potentially misleading)
                        let references_other_enum = all_constants.iter().any(|(enum_name, _)| {
                            value_text.contains(enum_name.as_str())
                                && !this_enum_names.contains(enum_name)
                        });

                        if references_other_enum {
                            // References a constant from a different enum - potentially misleading
                            let position = name_node.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                message: format!(
                                    "Constant '{}' encodes a potentially misleading relationship: {}. \
                                    If no permanent relationship exists, define constants independently.",
                                    name, value_text
                                ),
                                severity: self.severity(),
                                line: position.row + 1,
                                column: position.column + 1,
                                file_path: String::new(),
                                suggestion: Some(format!(
                                    "Either define '{}' with its literal value or ensure the relationship with {} is permanent and accurate",
                                    name, value_text
                                )),
                                requires_manual_review: Some(true),
                            });
                        }
                    }
                }
            }
        }

        // If all enumerators have explicit values AND there are 3 or more members, this is a
        // protocol/register/command enum — the programmer deliberately assigned every value
        // (e.g. wire-format spec, CAN command IDs).  There is no implicit relationship to
        // encode; skip the pair-offset check.  2-member enums like {IN_STR_LEN=18, OUT_STR_LEN=20}
        // are the canonical DCL08-C example and are still checked.
        if enum_values.len() == enumerators.len() && enumerators.len() >= 3 {
            return;
        }

        // If all explicit values form a consecutive integer sequence (0,1,2,... or 1,2,3,...),
        // this is just making enum numbering explicit — not an encoded relationship.
        // Common patterns: {SUCCESS=0, FAIL=1}, {CHARGE=1, DISCHARGE=2}, {A=0, B=1, C=2}.
        if enum_values.len() >= 2 {
            let mut sorted_vals: Vec<i64> = enum_values.iter().map(|(_, v, _)| *v).collect();
            sorted_vals.sort();
            let is_consecutive = sorted_vals.windows(2).all(|w| w[1] == w[0] + 1);
            if is_consecutive {
                return;
            }
        }

        // Check if any pair of values might have a relationship
        // For noncompliant_1: IN_STR_LEN=18, OUT_STR_LEN=20 (20 = 18+2)
        if enum_values.len() >= 2 {
            // Check all pairs for simple arithmetic relationships
            for i in 0..enum_values.len() {
                for j in (i + 1)..enum_values.len() {
                    let (name1, val1, _) = &enum_values[i];
                    let (name2, val2, pos2) = &enum_values[j];

                    // Check if val2 could be expressed as val1 + offset
                    if val2 > val1 {
                        let offset = val2 - val1;
                        // Flag small offsets (like +2, +3) as potential relationships
                        if offset > 0 && offset <= 10 {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                message: format!(
                                    "Constants '{}' and '{}' may have a relationship ({} = {} + {}). \
                                    Consider encoding: {} = {} + {}",
                                    name1, name2, val2, val1, offset, name2, name1, offset
                                ),
                                severity: self.severity(),
                                line: pos2.row + 1,
                                column: pos2.column + 1,
                                file_path: String::new(),
                                suggestion: Some(format!(
                                    "enum {{ {} = {}, {} = {} + {} }};",
                                    name1, val1, name2, name1, offset
                                )),
                                requires_manual_review: Some(true),
                            });
                        }
                    }
                }
            }
        }
    }

    #[allow(dead_code)]
    fn contains_reference_with_arithmetic(
        &self,
        value_text: &str,
        known_values: &[(&str, i64, tree_sitter::Point)],
    ) -> bool {
        // Check if the value contains a reference to another enum constant plus arithmetic
        for (name, _, _) in known_values {
            if value_text.contains(name) && (value_text.contains('+') || value_text.contains('-')) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = Dcl08C;
        assert_eq!(rule.rule_id(), "DCL08-C");
    }

    #[test]
    fn test_severity() {
        let rule = Dcl08C;
        assert_eq!(rule.severity(), Severity::Low);
    }
}
