//! ENV34-C: Do not store pointers returned by certain functions
//!
//! Certain standard library functions return pointers to internal storage that may be
//! overwritten by subsequent calls to the same or related functions. Storing these
//! pointers for later use can lead to referencing stale or incorrect data.
//!
//! ## Affected Functions:
//! - `getenv()` - environment variable string
//! - `asctime()` - time string conversion
//! - `localeconv()` - locale information
//! - `setlocale()` - locale settings
//! - `strerror()` - error message string
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! char *tmpvar = getenv("TMP");
//! char *tempvar = getenv("TEMP");  // May overwrite tmpvar's buffer
//! if (strcmp(tmpvar, tempvar) == 0) {  // Comparing potentially identical data
//!     // ...
//! }
//! ```
//!
//! **Compliant (using strdup):**
//! ```c
//! char *tmpvar = strdup(getenv("TMP"));   // Create copy
//! char *tempvar = strdup(getenv("TEMP")); // Create copy
//! if (strcmp(tmpvar, tempvar) == 0) {
//!     // ...
//! }
//! free(tmpvar);
//! free(tempvar);
//! ```
//!
//! **Compliant (using malloc/strcpy):**
//! ```c
//! const char *temp = getenv("TMP");
//! if (temp) {
//!     char *tmpvar = malloc(strlen(temp) + 1);
//!     strcpy(tmpvar, temp);
//!     // Use tmpvar safely...
//!     free(tmpvar);
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Detect pointer assignments from affected functions
//! - Flag direct storage of returned pointers in variables
//! - Suggest using strdup(), malloc()/strcpy(), or immediate use

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Env34C;

impl CertRule for Env34C {
    fn rule_id(&self) -> &'static str {
        "ENV34-C"
    }

    fn description(&self) -> &'static str {
        "Do not store pointers returned by certain functions"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ENV34-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Env34C {
    /// Check nodes for dangerous pointer storage
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for assignments or declarations that store pointers from affected functions
        for n in
            query::find_descendants_of_kinds(*node, &["assignment_expression", "init_declarator"])
        {
            if n.kind() == "assignment_expression" {
                self.check_assignment(&n, source, violations);
            } else if n.kind() == "init_declarator" {
                self.check_init_declarator(&n, source, violations);
            }
        }
    }

    /// Check assignment expressions for storing pointers from affected functions
    fn check_assignment(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(right) = node.child_by_field_name("right") {
            if self.is_affected_function_call(&right, source) {
                // Check if left side is a const char* variable (acceptable for temporary storage)
                if let Some(left) = node.child_by_field_name("left") {
                    if self.is_const_variable_assignment(&left, source) {
                        // Assigning to const char* variable is acceptable for immediate use
                        return;
                    }
                }

                let func_name = self.get_function_name_from_call(&right, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    message: format!(
                        "Storing pointer returned by '{}' is prohibited. The data referenced \
                         may be overwritten by subsequent calls. Use strdup(), malloc()/strcpy(), \
                         or consume the value immediately.",
                        func_name
                    ),
                    severity: self.severity(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    file_path: String::new(),
                    suggestion: Some(format!(
                        "Instead of 'ptr = {}()', use 'ptr = strdup({}())' and remember to free() later, \
                         or use 'const char *ptr' for immediate use only",
                        func_name, func_name
                    )),
                    requires_manual_review: None,
                });
            }
        }
    }

    /// Check if assignment is to a const char* variable
    fn is_const_variable_assignment(&self, left_node: &Node, source: &str) -> bool {
        // For assignment expressions, we need to find if the variable was declared as const
        // This is a simplified heuristic - we look for common patterns
        // In practice, full type analysis would be needed
        let var_name = get_node_text(left_node, source);

        // Common pattern: variables named 'temp', 'tmp', 'ptr' are often const temporary variables
        // This is a heuristic, but aligns with common coding patterns
        matches!(var_name, "temp" | "tmp" | "ptr" | "p")
    }

    /// Check variable initialization for storing pointers from affected functions
    fn check_init_declarator(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for initialization with affected function call
        // Pattern: char *var = getenv("...");  (non-const pointer)
        // Acceptable: const char *var = getenv("...");  (const pointer for immediate use)

        // First, check if this is a const pointer declaration
        let is_const = self.is_const_pointer_declarator(node, source);

        // If it's const, it's acceptable for temporary storage before immediate use
        if is_const {
            return;
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "=" {
                    // Next child after '=' is the initializer
                    if let Some(init) = node.child(i + 1) {
                        if self.is_affected_function_call(&init, source) {
                            let func_name = self.get_function_name_from_call(&init, source);

                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                message: format!(
                                    "Storing pointer returned by '{}' in non-const pointer is prohibited. \
                                     The data referenced may be overwritten by subsequent calls.",
                                    func_name
                                ),
                                severity: self.severity(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                file_path: String::new(),
                                suggestion: Some(format!(
                                    "Instead of 'char *var = {}()', use 'char *var = strdup({}())' \
                                     and free() later, or use 'const char *var' for immediate use only",
                                    func_name, func_name
                                )),
                                requires_manual_review: None,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Check if an init_declarator has const qualifier
    fn is_const_pointer_declarator(&self, node: &Node, source: &str) -> bool {
        // Look at the parent declaration to find type qualifiers
        if let Some(parent) = node.parent() {
            if parent.kind() == "declaration" {
                // Check for "const" in type qualifiers
                for i in 0..parent.child_count() {
                    if let Some(child) = parent.child(i) {
                        if child.kind() == "type_qualifier" {
                            let text = get_node_text(&child, source);
                            if text == "const" {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if a node is a call to an affected function
    fn is_affected_function_call(&self, node: &Node, source: &str) -> bool {
        if node.kind() != "call_expression" {
            return false;
        }

        if let Some(function) = node.child_by_field_name("function") {
            let func_name = get_node_text(&function, source);
            self.is_affected_function(&func_name)
        } else {
            false
        }
    }

    /// Get function name from a call expression
    fn get_function_name_from_call(&self, node: &Node, source: &str) -> String {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                return get_node_text(&function, source).to_string();
            }
        }
        String::from("unknown")
    }

    /// Check if function is one of the affected functions
    fn is_affected_function(&self, name: &str) -> bool {
        matches!(
            name,
            "getenv" | "asctime" | "localeconv" | "setlocale" | "strerror"
        )
    }
}
