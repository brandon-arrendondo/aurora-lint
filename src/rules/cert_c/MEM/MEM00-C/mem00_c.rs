//! MEM00-C: Allocate and free memory in the same module, at the same level of abstraction
//!
//! Memory should be freed in the same function or module where it was allocated.
//! Freeing memory passed as a parameter breaks this principle.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int verify_size(char *list, size_t size) {
//!     if (size < MIN_SIZE) {
//!         free(list);  // Freeing parameter - wrong abstraction level
//!         return -1;
//!     }
//!     return 0;
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! int verify_size(char *list, size_t size) {
//!     if (size < MIN_SIZE) {
//!         return -1;  // Let caller handle freeing
//!     }
//!     return 0;
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::function_summary::extract_function_name;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Mem00C;

impl CertRule for Mem00C {
    fn rule_id(&self) -> &'static str {
        "MEM00-C"
    }

    fn description(&self) -> &'static str {
        "Allocate and free memory in the same module, at the same level of abstraction"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "MEM00-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.find_parameter_frees(node, source, violations);
    }
}

impl Mem00C {
    /// Find functions that free memory passed as parameters
    fn find_parameter_frees(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for func_def in query::find_descendants_of_kind(*node, "function_definition") {
            // A function whose own name signals it's a destructor is
            // SUPPOSED to free what's passed in -- that's the entire point
            // of a "free_X"/"X_destroy"/"module_cleanup_thing" helper, not
            // a same-abstraction-level violation (task 318).
            if let Some(name) = extract_function_name(&func_def, source) {
                if Self::name_has_destructor_token(&name) {
                    continue;
                }
            }

            // Get parameter names
            let params = self.get_pointer_params(&func_def, source);

            if !params.is_empty() {
                // Check if any free() calls are made on parameters
                if let Some(body) = func_def.child_by_field_name("body") {
                    self.check_free_on_params(&body, source, &params, violations);
                }
            }
        }
    }

    /// Get pointer parameter names from function
    fn get_pointer_params(&self, func_def: &Node, source: &str) -> HashSet<String> {
        let mut params = HashSet::new();

        if let Some(declarator) = func_def.child_by_field_name("declarator") {
            // Find parameter list
            for i in 0..declarator.child_count() {
                if let Some(child) = declarator.child(i) {
                    if child.kind() == "parameter_list" {
                        // Extract each parameter
                        for j in 0..child.child_count() {
                            if let Some(param) = child.child(j) {
                                if param.kind() == "parameter_declaration" {
                                    let param_text = get_node_text(&param, source);
                                    // Check if it's a pointer parameter
                                    if param_text.contains('*') {
                                        if let Some(name) = self.extract_param_name(&param, source)
                                        {
                                            params.insert(name);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        params
    }

    /// Check if free() is called on any parameter
    fn check_free_on_params(
        &self,
        node: &Node,
        source: &str,
        params: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                if func_name == "free" {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        // Check if argument is a parameter
                        for i in 0..args.child_count() {
                            if let Some(arg) = args.child(i) {
                                let arg_text = get_node_text(&arg, source).trim().to_string();
                                if params.contains(&arg_text) {
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        message: format!(
                                            "Freeing parameter '{}'. Memory should be freed at \
                                             the same abstraction level where it was allocated.",
                                            arg_text
                                        ),
                                        severity: self.severity(),
                                        line: node.start_position().row + 1,
                                        column: node.start_position().column + 1,
                                        file_path: String::new(),
                                        suggestion: Some(
                                            "Return error code and let caller handle deallocation"
                                                .to_string(),
                                        ),
                                        requires_manual_review: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Extract parameter name
    fn extract_param_name(&self, param: &Node, source: &str) -> Option<String> {
        // Look for identifier in the parameter declaration
        for i in 0..param.child_count() {
            if let Some(child) = param.child(i) {
                if child.kind() == "pointer_declarator" {
                    return self.find_identifier(&child, source);
                }
                if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }

    /// Find identifier in node
    fn find_identifier(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = self.find_identifier(&child, source) {
                    return Some(name);
                }
            }
        }
        None
    }

    /// Does `name` contain a destructor/cleanup action word as a whole
    /// underscore-delimited token (e.g. `hostapd_config_free_radius`,
    /// `hostapd_cleanup_iface`, `release_resources`)? Unlike
    /// [`is_deallocation_call_name`]'s prefix/suffix-only check, this also
    /// catches the common `<module>_<action>_<subject>` naming convention
    /// where the action word sits in the middle of a compound identifier
    /// (task 318 -- hostap's `hostapd_config_free_radius` doesn't start
    /// with `free_` or end with `_free`, but is unambiguously a
    /// dedicated-cleanup helper).
    fn name_has_destructor_token(name: &str) -> bool {
        const DESTRUCTOR_TOKENS: &[&str] = &[
            "free", "destroy", "delete", "del", "cleanup", "release", "close", "deinit",
            "teardown", "uninit", "fini",
        ];
        name.split('_')
            .any(|tok| DESTRUCTOR_TOKENS.contains(&tok.to_lowercase().as_str()))
    }
}
