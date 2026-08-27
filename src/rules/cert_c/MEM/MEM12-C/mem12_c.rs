//! MEM12-C: Consider using a goto chain when leaving a function on error when using and releasing resources
//!
//! When a function acquires multiple resources (files, memory) and can fail at multiple points,
//! error paths must properly release all previously acquired resources. Failing to do so causes
//! resource leaks. The goto chain pattern is recommended for managing multiple resources cleanly.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! errno_t do_something(void) {
//!     FILE *fin1, *fin2;
//!     fin1 = fopen("file1", "r");
//!     if (fin1 == NULL) return errno;
//!
//!     fin2 = fopen("file2", "r");
//!     if (fin2 == NULL) {
//!         fclose(fin1);
//!         return errno;
//!     }
//!
//!     object_t *obj = malloc(sizeof(object_t));
//!     if (obj == NULL) {
//!         fclose(fin1);
//!         return errno;  // ERROR: fin2 not closed!
//!     }
//!     // ...
//! }
//! ```
//!
//! **Compliant (goto chain):**
//! ```c
//! errno_t do_something(void) {
//!     errno_t ret_val = NOERR;
//!     FILE *fin1 = fopen("file1", "r");
//!     if (fin1 == NULL) goto FAIL_FIN1;
//!
//!     FILE *fin2 = fopen("file2", "r");
//!     if (fin2 == NULL) goto FAIL_FIN2;
//!
//!     object_t *obj = malloc(sizeof(object_t));
//!     if (obj == NULL) goto FAIL_OBJ;
//!
//! SUCCESS:
//!     free(obj);
//! FAIL_OBJ:
//!     fclose(fin2);
//! FAIL_FIN2:
//!     fclose(fin1);
//! FAIL_FIN1:
//!     return ret_val;
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::macro_expand::{
    collect_function_macros, macro_frees_param_indices, FunctionMacro,
};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::call_roles;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Mem12C;

impl CertRule for Mem12C {
    fn rule_id(&self) -> &'static str {
        "MEM12-C"
    }

    fn description(&self) -> &'static str {
        "Consider using a goto chain when leaving a function on error when using and releasing resources"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MEM12-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Function-like macro definitions visible in this file, so a
        // cleanup macro (e.g. `SAFE_FREE`, `mosquitto_FREE`) is recognized
        // as a deallocation the same as a bare free()/fclose()/close() call
        // (task 315).
        let function_macros = collect_function_macros(node, source);

        // Check function definitions, including nested ones (though uncommon in C)
        for func_node in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function(&func_node, source, &function_macros, &mut violations);
        }

        violations
    }
}

impl Mem12C {
    /// Check a function for resource leak issues
    fn check_function(
        &self,
        func_node: &Node,
        source: &str,
        function_macros: &HashMap<String, FunctionMacro>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get function body
        let body = match func_node.child_by_field_name("body") {
            Some(b) => b,
            None => return,
        };

        // Track all resource allocations and deallocations in this function
        let mut allocations: Vec<(String, usize)> = Vec::new(); // (var_name, line)
        let mut deallocations: Vec<(String, usize)> = Vec::new(); // (var_name, line)

        self.find_allocations(&body, source, &mut allocations);
        self.find_deallocations(&body, source, function_macros, &mut deallocations);

        // Find return statements and check if they leak resources
        self.check_early_returns(&body, source, &allocations, &deallocations, violations);
    }

    /// Find all resource allocations (fopen, malloc, etc.)
    fn find_allocations(&self, node: &Node, source: &str, allocations: &mut Vec<(String, usize)>) {
        for n in
            query::find_descendants_of_kinds(*node, &["assignment_expression", "init_declarator"])
        {
            if n.kind() == "assignment_expression" {
                if let (Some(left), Some(right)) = (
                    n.child_by_field_name("left"),
                    n.child_by_field_name("right"),
                ) {
                    let var_name = get_node_text(&left, source).trim().to_string();
                    let right_text = get_node_text(&right, source);

                    // Check if right side is a resource allocation
                    if call_roles::is_resource_acquisition_text(&right_text) {
                        let line = n.start_position().row;
                        allocations.push((var_name, line));
                    }
                }
            } else if n.kind() == "init_declarator" {
                // Handle declarations with initialization: FILE *fp = fopen(...)
                if let Some(value) = n.child_by_field_name("value") {
                    if let Some(declarator) = n.child_by_field_name("declarator") {
                        let var_name = get_node_text(&declarator, source).trim().to_string();
                        let value_text = get_node_text(&value, source);

                        if call_roles::is_resource_acquisition_text(&value_text) {
                            let line = n.start_position().row;
                            allocations.push((var_name, line));
                        }
                    }
                }
            }
        }
    }

    /// Find all resource deallocations (fclose, free, etc.)
    fn find_deallocations(
        &self,
        node: &Node,
        source: &str,
        function_macros: &HashMap<String, FunctionMacro>,
        deallocations: &mut Vec<(String, usize)>,
    ) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = n.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                let Some(arguments) = n.child_by_field_name("arguments") else {
                    continue;
                };

                // Check if it's a deallocation function, or a function-like
                // macro whose body releases one of its arguments (task 315).
                let arg_idx =
                    if func_name == "fclose" || func_name == "free" || func_name == "close" {
                        Some(0)
                    } else {
                        macro_frees_param_indices(function_macros, &func_name)
                            .into_iter()
                            .next()
                    };

                if let Some(arg_idx) = arg_idx {
                    if let Some(arg) = nth_call_argument(&arguments, arg_idx, source) {
                        let line = n.start_position().row;
                        deallocations.push((arg, line));
                    }
                }
            }
        }
    }

    /// Check early return statements for resource leaks
    fn check_early_returns(
        &self,
        node: &Node,
        _source: &str,
        allocations: &[(String, usize)],
        deallocations: &[(String, usize)],
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "return_statement") {
            let return_line = n.start_position().row;

            // Find which resources were allocated before this return
            let allocated_before: Vec<&String> = allocations
                .iter()
                .filter(|(_, alloc_line)| *alloc_line < return_line)
                .map(|(name, _)| name)
                .collect();

            // Find which resources were deallocated before this return
            let deallocated_before: HashSet<&str> = deallocations
                .iter()
                .filter(|(_, dealloc_line)| *dealloc_line < return_line)
                .map(|(name, _)| name.as_str())
                .collect();

            // Check if there are any leaked resources
            // (allocated but not deallocated before this return)
            let leaked: Vec<&str> = allocated_before
                .iter()
                .filter(|name| !deallocated_before.contains(name.as_str()))
                .map(|s| s.as_str())
                .collect();

            if !leaked.is_empty() && allocated_before.len() > 1 {
                // Only flag if multiple resources AND some are leaked
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    message: format!(
                        "Function returns without releasing all resources. Leaked: {}. \
                         Consider using goto chain for proper resource cleanup.",
                        leaked.join(", ")
                    ),
                    severity: self.severity(),
                    line: return_line + 1,
                    column: n.start_position().column + 1,
                    file_path: String::new(),
                    suggestion: Some(
                        "Use goto chain pattern with cleanup labels to ensure all resources are released"
                            .to_string(),
                    ),
                    requires_manual_review: None,
                });
            }
        }
    }
}

/// Return the text of the `idx`-th argument (skipping `(`, `)`, `,` punctuation
/// children) of a call's `arguments` node.
fn nth_call_argument(arguments: &Node, idx: usize, source: &str) -> Option<String> {
    let mut seen = 0usize;
    for i in 0..arguments.child_count() {
        let arg = arguments.child(i)?;
        if arg.kind() == "(" || arg.kind() == ")" || arg.kind() == "," {
            continue;
        }
        if seen == idx {
            return Some(get_node_text(&arg, source).trim().to_string());
        }
        seen += 1;
    }
    None
}
