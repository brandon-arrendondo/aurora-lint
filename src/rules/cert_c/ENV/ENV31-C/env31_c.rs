//! ENV31-C: Do not rely on an environment pointer following an operation that may invalidate it
//!
//! The envp argument to main() becomes invalidated after calls to setenv(),
//! putenv(), _putenv_s(), or unsetenv(). Using envp after such calls can lead
//! to undefined behavior because the environment array may have been reallocated.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int main(int argc, char *argv[], char *envp[]) {
//!     setenv("MY_VAR", "value", 1);
//!     puts(envp[0]);  // envp may be invalid
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! extern char **environ;
//! int main(void) {
//!     setenv("MY_VAR", "value", 1);
//!     puts(environ[0]);  // environ is always valid
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Env31C;

impl CertRule for Env31C {
    fn rule_id(&self) -> &'static str {
        "ENV31-C"
    }

    fn description(&self) -> &'static str {
        "Do not rely on an environment pointer following an operation that may invalidate it"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ENV31-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Find main function
        self.find_main_functions(node, source, &mut violations);

        violations
    }
}

impl Env31C {
    /// Find main function definitions and analyze envp usage
    fn find_main_functions(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let function_definitions = query::find_descendants_of_kind(*node, "function_definition");

        for func_def in function_definitions {
            if let Some(declarator) = func_def.child_by_field_name("declarator") {
                let func_name = self.get_function_name(&declarator, source);

                if func_name == "main" {
                    // Check if main has envp parameter
                    if let Some(envp_param) = self.find_envp_parameter(&declarator, source) {
                        // Analyze function body for environment modifications followed by envp usage
                        if let Some(body) = func_def.child_by_field_name("body") {
                            self.analyze_main_body(&body, source, &envp_param, violations);
                        }
                    }
                }
            }
        }
    }

    /// Get function name from declarator
    fn get_function_name(&self, declarator: &Node, source: &str) -> String {
        if declarator.kind() == "identifier" {
            return get_node_text(declarator, source).to_string();
        }

        // Check for function declarator
        if declarator.kind() == "function_declarator" {
            if let Some(name_node) = declarator.child_by_field_name("declarator") {
                return get_node_text(&name_node, source).to_string();
            }
        }

        // Recurse to find identifier
        for i in 0..declarator.child_count() {
            if let Some(child) = declarator.child(i) {
                let name = self.get_function_name(&child, source);
                if !name.is_empty() {
                    return name;
                }
            }
        }

        String::new()
    }

    /// Find envp parameter in main function signature
    fn find_envp_parameter(&self, declarator: &Node, source: &str) -> Option<String> {
        if declarator.kind() == "function_declarator" {
            if let Some(params) = declarator.child_by_field_name("parameters") {
                // Look for third parameter (envp)
                let mut param_count = 0;
                for i in 0..params.child_count() {
                    if let Some(child) = params.child(i) {
                        if child.kind() == "parameter_declaration" {
                            param_count += 1;
                            if param_count == 3 {
                                // This should be envp
                                let param_name = self.extract_param_name(&child, source);
                                if !param_name.is_empty() {
                                    return Some(param_name);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Recurse
        for i in 0..declarator.child_count() {
            if let Some(child) = declarator.child(i) {
                if let Some(envp) = self.find_envp_parameter(&child, source) {
                    return Some(envp);
                }
            }
        }

        None
    }

    /// Extract parameter name from parameter_declaration
    fn extract_param_name(&self, param: &Node, source: &str) -> String {
        for i in 0..param.child_count() {
            if let Some(child) = param.child(i) {
                if child.kind() == "pointer_declarator" || child.kind() == "array_declarator" {
                    // Look inside for identifier
                    let name = self.find_identifier(&child, source);
                    if !name.is_empty() {
                        return name;
                    }
                } else if child.kind() == "identifier" {
                    return get_node_text(&child, source).to_string();
                }
            }
        }
        String::new()
    }

    /// Find identifier in a node tree
    fn find_identifier(&self, node: &Node, source: &str) -> String {
        if node.kind() == "identifier" {
            return get_node_text(node, source).to_string();
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let name = self.find_identifier(&child, source);
                if !name.is_empty() {
                    return name;
                }
            }
        }

        String::new()
    }

    /// Analyze main function body for environment modifications followed by envp usage
    fn analyze_main_body(
        &self,
        body: &Node,
        source: &str,
        envp_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // First pass: find environment-modifying function calls
        let mut env_mod_line = None;
        let mut env_mod_func = String::new();
        self.find_env_modification(body, source, &mut env_mod_line, &mut env_mod_func);

        // Second pass: if environment was modified, find envp usage after that
        if let Some(mod_line) = env_mod_line {
            self.find_envp_usage_after(
                body,
                source,
                envp_name,
                mod_line,
                &env_mod_func,
                violations,
            );
        }
    }

    /// Find calls to environment-modifying functions
    fn find_env_modification(
        &self,
        node: &Node,
        source: &str,
        mod_line: &mut Option<usize>,
        mod_func: &mut String,
    ) {
        let found = query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            n.child_by_field_name("function").is_some_and(|function| {
                self.is_env_modifying_function(get_node_text(&function, source))
            })
        });

        if let Some(call) = found {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                let line = call.start_position().row + 1;
                *mod_line = Some(line);
                *mod_func = func_name.to_string();
            }
        }
    }

    /// Find usage of envp after environment modification
    fn find_envp_usage_after(
        &self,
        node: &Node,
        source: &str,
        envp_name: &str,
        mod_line: usize,
        mod_func: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let matches = query::find_descendants(*node, |n| {
            if n.kind() != "identifier" {
                return false;
            }
            get_node_text(&n, source) == envp_name && n.start_position().row + 1 > mod_line
        });

        for usage in matches {
            let usage_line = usage.start_position().row + 1;
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                message: format!(
                    "Using '{}' after call to '{}' on line {}. The environment pointer \
                     may be invalidated after environment-modifying functions. \
                     Use 'environ' global variable instead.",
                    envp_name, mod_func, mod_line
                ),
                severity: self.severity(),
                line: usage_line,
                column: usage.start_position().column + 1,
                file_path: String::new(),
                suggestion: Some(format!(
                    "Replace '{}' with 'extern char **environ' and use 'environ' instead",
                    envp_name
                )),
                requires_manual_review: None,
            });
        }
    }

    /// Check if function modifies the environment
    fn is_env_modifying_function(&self, name: &str) -> bool {
        matches!(
            name,
            "setenv" | "putenv" | "_putenv_s" | "unsetenv" | "_wputenv_s"
        )
    }
}
