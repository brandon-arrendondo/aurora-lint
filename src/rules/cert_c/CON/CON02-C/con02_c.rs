//! CON02-C: Do not use volatile as a synchronization primitive
//!
//! This rule detects the use of volatile variables as synchronization primitives
//! in multithreaded programs. The volatile keyword does not provide adequate
//! synchronization guarantees (atomicity, visibility, ordering).
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! volatile bool flag = false;
//!
//! void test() {
//!   while (!flag) {
//!     sleep(1000);
//!   }
//! }
//!
//! void wakeup() {
//!   flag = true;
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! #include <threads.h>
//! mtx_t flag;
//! int account_balance;
//!
//! int debit(unsigned int amount) {
//!   if (mtx_lock(&flag) == thrd_error) return -1;
//!   account_balance -= amount;
//!   if (mtx_unlock(&flag) == thrd_error) return -1;
//!   return 0;
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Detect global/static variables with volatile keyword used as bool/int flags
//! - Report violations for volatile variables that appear to be used for synchronization

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Con02C;

impl CertRule for Con02C {
    fn rule_id(&self) -> &'static str {
        "CON02-C"
    }

    fn description(&self) -> &'static str {
        "Do not use volatile as a synchronization primitive"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "CON02-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check for volatile declarations
        for decl_node in query::find_descendants_of_kind(*node, "declaration") {
            self.check_declaration(&decl_node, source, &mut violations);
        }

        violations
    }
}

impl Con02C {
    fn check_declaration(
        &self,
        decl_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if this declaration has volatile qualifier
        let has_volatile = self.has_volatile_qualifier(decl_node, source);

        // Check if this is a global/file-scope variable (not a local variable)
        let is_global = self.is_global_declaration(decl_node);

        // Get the variable name and type
        if let Some(var_info) = self.get_variable_info(decl_node, source) {
            // Check if this looks like a synchronization flag
            // We detect two cases:
            // 1. Variables with 'volatile' qualifier + flag type (definitely suspicious)
            // 2. Non-volatile variables that look like synchronization flags (name-based heuristic)
            let looks_like_sync_flag = self.looks_like_synchronization_flag(&var_info.name);
            let is_flag_typed = self.is_flag_type(&var_info.type_name);

            if is_global && is_flag_typed && (has_volatile || looks_like_sync_flag) {
                // Flag both volatile and non-volatile global flags
                let message = if has_volatile {
                    format!(
                        "Variable '{}' uses 'volatile' as a synchronization primitive. Use proper synchronization primitives (mutexes, condition variables, or atomic operations) instead.",
                        var_info.name
                    )
                } else {
                    format!(
                        "Global flag variable '{}' appears to be used for synchronization without proper primitives. Use mutexes, condition variables, or atomic operations instead.",
                        var_info.name
                    )
                };

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message,
                    file_path: String::new(),
                    line: var_info.line,
                    column: var_info.column,
                    suggestion: Some(
                        "Replace with proper synchronization primitives like mtx_t (C11 threads), pthread_mutex_t (POSIX), or atomic types (_Atomic)".to_string()
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn has_volatile_qualifier(&self, decl_node: &Node, source: &str) -> bool {
        // Look for "volatile" in type qualifiers
        let mut cursor = decl_node.walk();
        for child in decl_node.children(&mut cursor) {
            if child.kind() == "type_qualifier" {
                let text = get_node_text(&child, source);
                if text.trim() == "volatile" {
                    return true;
                }
            }
            // Check in storage_class_specifier or other nested nodes
            if self.check_volatile_in_node(&child, source) {
                return true;
            }
        }
        false
    }

    fn check_volatile_in_node(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            n.kind() == "type_qualifier" && get_node_text(&n, source).trim() == "volatile"
        })
        .is_some()
    }

    fn get_variable_info(&self, decl_node: &Node, source: &str) -> Option<VarInfo> {
        let mut cursor = decl_node.walk();
        let mut type_name = String::new();
        let mut var_name = String::new();
        let mut line = 0;
        let mut column = 0;

        // Extract type specifier
        for child in decl_node.children(&mut cursor) {
            if child.kind() == "primitive_type" || child.kind() == "type_identifier" {
                type_name = get_node_text(&child, source).to_string();
            }

            // Check init_declarator or declarator for variable name
            if child.kind() == "init_declarator" {
                if let Some(declarator) = child.child_by_field_name("declarator") {
                    var_name = get_node_text(&declarator, source).to_string();
                    line = declarator.start_position().row + 1;
                    column = declarator.start_position().column + 1;
                }
            } else if child.kind() == "declarator" || child.kind() == "identifier" {
                var_name = get_node_text(&child, source).to_string();
                line = child.start_position().row + 1;
                column = child.start_position().column + 1;
            }
        }

        if !var_name.is_empty() {
            Some(VarInfo {
                name: var_name,
                type_name,
                line,
                column,
            })
        } else {
            None
        }
    }

    fn is_flag_type(&self, type_name: &str) -> bool {
        // Common types used for synchronization flags
        matches!(
            type_name.trim(),
            "bool"
                | "_Bool"
                | "int"
                | "unsigned"
                | "unsigned int"
                | "long"
                | "unsigned long"
                | "short"
                | "unsigned short"
                | "char"
                | "unsigned char"
                | "sig_atomic_t"
        )
    }

    fn is_global_declaration(&self, decl_node: &Node) -> bool {
        // Check if the parent is a translation_unit (file scope)
        // or if there's no function_definition ancestor
        let mut current = decl_node.parent();
        while let Some(node) = current {
            match node.kind() {
                "translation_unit" => return true,
                "function_definition" | "compound_statement" => return false,
                _ => current = node.parent(),
            }
        }
        false
    }

    fn looks_like_synchronization_flag(&self, var_name: &str) -> bool {
        // Heuristic: variable names that commonly indicate synchronization flags
        let lower_name = var_name.to_lowercase();
        lower_name.contains("flag")
            || lower_name.contains("ready")
            || lower_name.contains("done")
            || lower_name.contains("stop")
            || lower_name.contains("running")
            || lower_name.contains("active")
            || lower_name.contains("enabled")
            || lower_name.contains("signal")
    }
}

#[derive(Debug)]
struct VarInfo {
    name: String,
    type_name: String,
    line: usize,
    column: usize,
}
