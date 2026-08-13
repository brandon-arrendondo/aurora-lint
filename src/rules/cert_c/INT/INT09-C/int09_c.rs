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
use crate::analyze::const_eval::{
    collect_macro_constants, try_evaluate_text_public, MacroConstantMap,
};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

// Track enumerator values and whether they're explicit.
#[derive(Debug)]
struct EnumValue {
    name: String,
    value: i64,
    is_explicit: bool,
    // True when the explicit value is derived from a prior enumerator's
    // NAME, either directly (`violet = indigo`) or through arithmetic on it
    // (`FOO_MAX = __FOO_AFTER_LAST - 1`, the standard MAX-sentinel idiom,
    // which by construction duplicates the last real member's value on
    // purpose). Referencing a named enumerator can't collide by accident
    // the way a numeric-literal collision can, so it's unambiguous
    // intentional duplication (CERT INT09-C's own exception).
    is_name_alias: bool,
    node: Node<'static>,
}

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

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_enum_duplicates(node, source, violations);
    }
}

impl Int09C {
    fn check_enum_duplicates(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let macros = collect_macro_constants(node, source);
        for n in query::find_descendants_of_kind(*node, "enum_specifier") {
            self.analyze_enum(&n, source, &macros, violations);
        }
    }

    fn analyze_enum(
        &self,
        enum_node: &Node,
        source: &str,
        macros: &MacroConstantMap,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Find the enumerator_list
        let enumerator_list = match Self::find_enumerator_list(enum_node) {
            Some(list) => list,
            None => return,
        };

        let mut enumerators: Vec<EnumValue> = Vec::new();
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

                    let (value, is_explicit, is_name_alias) =
                        if let Some(value_node) = child.child_by_field_name("value") {
                            let value_text = get_node_text(&value_node, source);
                            let trimmed = value_text.trim();
                            // An explicit value may reference a prior
                            // enumerator by name (e.g. `violet = indigo`)
                            // rather than a numeric literal; resolve it
                            // against what's been parsed so far before
                            // falling back to numeric parsing.
                            if let Some(aliased) = enumerators.iter().find(|e| e.name == trimmed) {
                                (aliased.value, true, true)
                            } else if let Some((v, used_enum_ref)) =
                                self.try_eval_enum_arith(trimmed, &enumerators)
                            {
                                (v, true, used_enum_ref)
                            } else if let Some(v) = try_evaluate_text_public(trimmed, macros) {
                                // Handles arithmetic on plain `#define` macros
                                // (e.g. curl's `CURLINFO_STRING + 1` idiom),
                                // which aren't prior enumerators so
                                // try_eval_enum_arith can't resolve them.
                                (v, true, false)
                            } else {
                                (self.parse_constant_value(trimmed), true, false)
                            }
                        } else {
                            (current_value, false, false)
                        };

                    // SAFETY: We're storing the node which has the same lifetime as the source
                    // The violations vec will be used within the same scope
                    let static_node: Node<'static> =
                        unsafe { std::mem::transmute::<Node, Node<'static>>(child) };

                    enumerators.push(EnumValue {
                        name: name.to_string(),
                        value,
                        is_explicit,
                        is_name_alias,
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
                // A direct by-name alias (e.g. `violet = indigo`) can't be
                // an accidental collision -- it's unambiguous intentional
                // duplication, regardless of whether the aliased value
                // happened to be implicit.
                let has_name_alias = enum_list.iter().any(|e| e.is_name_alias);

                if has_implicit && !has_name_alias {
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

    /// Try to evaluate a simple `LHS (+|-) RHS` expression where either side
    /// may be a numeric literal or the name of a prior enumerator in the
    /// same enum (e.g. `NUM_FOO - 1`, `__FOO_AFTER_LAST - 1`). Returns the
    /// computed value plus whether either operand was a named-enumerator
    /// reference (as opposed to two plain numeric literals).
    ///
    /// Scans for the operator right-to-left so the split lands on the
    /// top-level `+`/`-` for the single-operator idiom this rule cares
    /// about; it does not attempt general expression parsing (precedence,
    /// parens, multiple operators).
    fn try_eval_enum_arith(&self, text: &str, enumerators: &[EnumValue]) -> Option<(i64, bool)> {
        for (idx, ch) in text.char_indices().rev() {
            if (ch == '+' || ch == '-') && idx != 0 {
                let left = text[..idx].trim();
                let right = text[idx + ch.len_utf8()..].trim();
                if left.is_empty() || right.is_empty() {
                    continue;
                }
                if let (Some((lval, lref)), Some((rval, rref))) = (
                    self.resolve_enum_operand(left, enumerators),
                    self.resolve_enum_operand(right, enumerators),
                ) {
                    let result = if ch == '+' { lval + rval } else { lval - rval };
                    return Some((result, lref || rref));
                }
            }
        }
        None
    }

    /// Resolve one operand of an enum-initializer arithmetic expression:
    /// either a prior enumerator's name (returns its value, `true`) or a
    /// numeric literal (returns its value, `false`).
    fn resolve_enum_operand(&self, text: &str, enumerators: &[EnumValue]) -> Option<(i64, bool)> {
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        if let Some(e) = enumerators.iter().find(|e| e.name == text) {
            return Some((e.value, true));
        }
        if text.starts_with("0x") || text.starts_with("0X") {
            return i64::from_str_radix(&text[2..], 16).ok().map(|v| (v, false));
        }
        if text.chars().all(|c| c.is_ascii_digit()) {
            return text.parse::<i64>().ok().map(|v| (v, false));
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
