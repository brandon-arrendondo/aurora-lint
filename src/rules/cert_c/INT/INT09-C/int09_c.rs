//! INT09-C: Ensure enumeration constants map to unique values
//!
//! When enumeration constants are assigned explicit values, mixing explicit and
//! implicit assignments can lead to unintentional duplicate values. This can cause
//! problems in switch statements where multiple case labels may have the same value.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! enum Color { red=4, orange, yellow, green, blue, indigo=6, violet };
//! // yellow=6 (implicit), indigo=6 (explicit) - DUPLICATE!
//! // green=7 (implicit), violet=7 (implicit) - DUPLICATE!
//! ```
//!
//! **Compliant:**
//! ```c
//! enum Color { red, orange, yellow, green, blue, indigo, violet };
//! // All implicit - sequential 0-6, no duplicates
//!
//! enum Color { red=4, orange, yellow, green, blue, indigo, violet };
//! // Only first explicit, rest sequential - no duplicates
//!
//! enum Color { red=4, orange=5, yellow=6, green=7, blue=8, indigo=6, violet=7 };
//! // All explicit - duplicates are INTENTIONAL (allowed)
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Int09C;

impl CertRule for Int09C {
    fn rule_id(&self) -> &'static str {
        "INT09-C"
    }

    fn description(&self) -> &'static str {
        "Ensure enumeration constants map to unique values"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "INT09-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_enum_duplicates(node, source, &mut violations);
        violations
    }
}

impl Int09C {
    fn check_enum_duplicates(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "enum_specifier") {
            self.analyze_enum(&n, source, violations);
        }
    }

    fn analyze_enum(&self, enum_node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Find the enumerator_list
        let enumerator_list = match Self::find_enumerator_list(enum_node) {
            Some(list) => list,
            None => return,
        };

        // Track enumerator values and whether they're explicit
        #[derive(Debug)]
        struct EnumValue {
            name: String,
            value: i64,
            is_explicit: bool,
            node: Node<'static>,
        }

        let mut enumerators = Vec::new();
        let mut current_value: i64 = 0;

        // Parse all enumerators
        for i in 0..enumerator_list.child_count() {
            if let Some(child) = enumerator_list.child(i) {
                if child.kind() == "enumerator" {
                    let name = if let Some(name_node) = child.child_by_field_name("name") {
                        get_node_text(&name_node, source)
                    } else {
                        continue;
                    };

                    let (value, is_explicit) =
                        if let Some(value_node) = child.child_by_field_name("value") {
                            let value_text = get_node_text(&value_node, source);
                            let parsed_value = self.parse_constant_value(value_text);
                            (parsed_value, true)
                        } else {
                            (current_value, false)
                        };

                    // SAFETY: We're storing the node which has the same lifetime as the source
                    // The violations vec will be used within the same scope
                    let static_node: Node<'static> =
                        unsafe { std::mem::transmute::<Node, Node<'static>>(child) };

                    enumerators.push(EnumValue {
                        name: name.to_string(),
                        value,
                        is_explicit,
                        node: static_node,
                    });

                    current_value = value + 1;
                }
            }
        }

        // Check for duplicates where at least one is implicit (unintentional)
        let mut value_map: HashMap<i64, Vec<&EnumValue>> = HashMap::new();
        for enumerator in &enumerators {
            value_map
                .entry(enumerator.value)
                .or_default()
                .push(enumerator);
        }

        for (value, enum_list) in value_map {
            if enum_list.len() > 1 {
                // Check if at least one is implicit (unintentional duplicate)
                let has_implicit = enum_list.iter().any(|e| !e.is_explicit);

                if has_implicit {
                    // Report violation for all duplicates
                    for enumerator in enum_list {
                        let explicit_status = if enumerator.is_explicit {
                            "explicitly"
                        } else {
                            "implicitly"
                        };

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: format!(
                                "Enumeration constant '{}' has duplicate value {} ({}). \
                                 Mixing explicit and implicit enum value assignments can \
                                 cause unintentional duplicates.",
                                enumerator.name, value, explicit_status
                            ),
                            severity: self.severity(),
                            line: enumerator.node.start_position().row + 1,
                            column: enumerator.node.start_position().column + 1,
                            file_path: String::new(),
                            suggestion: Some(
                                "Either use all implicit values, or make all assignments explicit"
                                    .to_string(),
                            ),
                            requires_manual_review: Some(false),
                        });
                    }
                }
            }
        }
    }

    fn find_enumerator_list<'a>(enum_node: &'a Node<'a>) -> Option<Node<'a>> {
        for i in 0..enum_node.child_count() {
            if let Some(child) = enum_node.child(i) {
                if child.kind() == "enumerator_list" {
                    return Some(child);
                }
            }
        }
        None
    }

    fn parse_constant_value(&self, text: &str) -> i64 {
        let text = text.trim();

        // Handle hex
        if text.starts_with("0x") || text.starts_with("0X") {
            return i64::from_str_radix(&text[2..], 16).unwrap_or(0);
        }

        // Handle octal
        if text.starts_with('0') && text.len() > 1 {
            return i64::from_str_radix(text, 8).unwrap_or(0);
        }

        // Handle decimal
        text.parse::<i64>().unwrap_or(0)
    }
}
