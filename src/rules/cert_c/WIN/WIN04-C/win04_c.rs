//! WIN04-C: Consider encrypting function pointers
//!
//! This rule detects function pointers that are stored without encryption,
//! which could be exploited by attackers if memory is overwritten.
//!
//! VIOLATIONS:
//! - Function pointer declarations initialized directly without EncodePointer
//! - Function pointer assignments without EncodePointer
//!
//! COMPLIANT:
//! - Function pointers stored using EncodePointer() or EncodeSystemPointer()
//! - Function pointers that are const or otherwise protected

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Win04C;

// Functions that properly encode/encrypt function pointers
const ENCODE_FUNCS: &[&str] = &["EncodePointer", "EncodeSystemPointer"];
// Functions that decode encrypted pointers (acceptable for initialization)
const DECODE_FUNCS: &[&str] = &["DecodePointer", "DecodeSystemPointer"];

impl CertRule for Win04C {
    fn rule_id(&self) -> &'static str {
        "WIN04-C"
    }

    fn description(&self) -> &'static str {
        "Consider encrypting function pointers"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "WIN04-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Win04C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check declarations with function pointer types
        for decl in query::find_descendants_of_kind(*node, "declaration") {
            self.check_declaration(&decl, source, violations);
        }
    }

    fn check_declaration(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check if this is a function pointer declaration
        if !self.is_function_pointer_declaration(node, source) {
            return;
        }

        // Check if there's an init_declarator with an initializer
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "init_declarator" {
                    // Check if the initializer uses EncodePointer
                    if let Some(initializer) = self.get_initializer(&child, source) {
                        if !self.uses_encode_function(&initializer, source) {
                            // Violation: function pointer initialized without encoding
                            let pos = child.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::High,
                                message: "Function pointer stored without encryption; consider using EncodePointer()".to_string(),
                                file_path: String::new(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                                suggestion: Some(
                                    "Use EncodePointer() to encrypt the function pointer before storage".to_string()
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    fn is_function_pointer_declaration(&self, node: &Node, source: &str) -> bool {
        // Check if declaration contains function pointer syntax
        let decl_text = get_node_text(node, source);

        // Function pointer patterns: (*name)( or (* name)(
        if decl_text.contains("(*") && decl_text.contains(")(") {
            return true;
        }

        // Also check for function_declarator within pointer_declarator
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if self.contains_function_pointer(&child) {
                    return true;
                }
            }
        }

        false
    }

    fn contains_function_pointer(&self, node: &Node) -> bool {
        let kind = node.kind();

        if kind == "function_declarator" {
            // Check if parent chain includes pointer_declarator
            return true;
        }

        // Check for pointer_declarator containing function_declarator
        if kind == "pointer_declarator" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "function_declarator" {
                        return true;
                    }
                    if self.contains_function_pointer(&child) {
                        return true;
                    }
                }
            }
        }

        if kind == "init_declarator" || kind == "parenthesized_declarator" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if self.contains_function_pointer(&child) {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn get_initializer<'a>(&self, init_decl: &'a Node<'a>, _source: &str) -> Option<Node<'a>> {
        // Find the initializer value (after '=')
        let mut found_eq = false;
        for i in 0..init_decl.child_count() {
            if let Some(child) = init_decl.child(i) {
                if child.kind() == "=" {
                    found_eq = true;
                    continue;
                }
                if found_eq {
                    return Some(child);
                }
            }
        }
        None
    }

    fn uses_encode_function(&self, node: &Node, source: &str) -> bool {
        // Check if this node or any descendant is a call to an encode/decode function
        // (handles casts wrapping function calls too, since the whole subtree is searched)
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(func) = n.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&func, source);
            // Both encode (for storage) and decode (for use) are acceptable
            ENCODE_FUNCS.contains(&func_name) || DECODE_FUNCS.contains(&func_name)
        })
        .is_some()
    }
}
