//! API05-C: Use conformant array parameters
//!
//! Since C99, C supports conformant array parameters with extended syntax that
//! allows specifying array bounds using variables from the parameter list.
//! Conformant array parameters document the expected size relationship and can
//! help compilers and static analysis tools detect buffer overflows.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! // Plain pointer - doesn't document size relationship
//! void my_memset(char* p, size_t n, char v) {
//!     memset(p, v, n);
//! }
//!
//! // Array size uses variable declared AFTER it (invalid)
//! void my_memset(char p[n], size_t n, char v) {
//!     memset(p, v, n);
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! // Size parameter declared BEFORE array parameter
//! void my_memset(size_t n, char p[n], char v) {
//!     memset(p, v, n);
//! }
//!
//! // K&R style with semicolon (GCC extension)
//! void my_memset(size_t n; char p[n], size_t n, char v) {
//!     memset(p, v, n);
//! }
//! ```

use crate::manifest::{RuleCategory, Severity};
use crate::rules::{CertRule, RuleViolation};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Api05C;

impl CertRule for Api05C {
    fn rule_id(&self) -> &'static str {
        "API05-C"
    }

    fn description(&self) -> &'static str {
        "Use conformant array parameters"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "API05-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for decl in query::find_descendants_of_kinds(*node, &["function_definition", "declaration"])
        {
            if let Some(declarator) = decl.child_by_field_name("declarator") {
                self.check_function_declarator(&declarator, source, &mut violations);
            }
        }
        violations
    }
}

impl Api05C {
    fn check_function_declarator(
        &self,
        declarator: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Find function_declarator nodes
        if declarator.kind() == "function_declarator" {
            if let Some(params) = declarator.child_by_field_name("parameters") {
                self.check_parameters(&params, source, violations);
            }
        } else if declarator.kind() == "pointer_declarator" {
            // Handle pointer declarators (e.g., *function_name(...))
            if let Some(child) = declarator.named_child(0) {
                self.check_function_declarator(&child, source, violations);
            }
        }
    }

    fn check_parameters(
        &self,
        params_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if this uses K&R style (semicolon in parameter list)
        let params_text = get_node_text(params_node, source);
        if params_text.contains(';') {
            // K&R style is compliant, skip check
            return;
        }

        // Collect all parameter info in order
        let mut param_names: Vec<String> = Vec::new();
        let mut param_nodes: Vec<Node> = Vec::new();
        let mut has_size_t_param = false;

        for i in 0..params_node.child_count() {
            if let Some(child) = params_node.child(i) {
                if child.kind() == "parameter_declaration" {
                    if let Some(name) = self.get_parameter_name(&child, source) {
                        param_names.push(name);
                        param_nodes.push(child);

                        // Check if this is a size_t parameter
                        if let Some(type_node) = child.child_by_field_name("type") {
                            let type_text = get_node_text(&type_node, source);
                            if type_text.contains("size_t") {
                                has_size_t_param = true;
                            }
                        }
                    }
                }
            }
        }

        // Check each parameter for conformant array issues
        for (idx, param_node) in param_nodes.iter().enumerate() {
            let declared_names: HashSet<_> = param_names[..idx].iter().cloned().collect();
            self.check_parameter_conformance(
                param_node,
                source,
                &declared_names,
                has_size_t_param,
                violations,
            );
        }
    }

    fn get_parameter_name(&self, param: &Node, source: &str) -> Option<String> {
        // Try to find the parameter name
        if let Some(declarator) = param.child_by_field_name("declarator") {
            return self.extract_declarator_name(&declarator, source);
        }
        None
    }

    #[allow(clippy::only_used_in_recursion)]
    fn extract_declarator_name(&self, declarator: &Node, source: &str) -> Option<String> {
        match declarator.kind() {
            "identifier" => Some(get_node_text(declarator, source).to_string()),
            "pointer_declarator" | "array_declarator" | "function_declarator" => {
                // Recurse to find the identifier
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if let Some(name) = self.extract_declarator_name(&child, source) {
                            return Some(name);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn check_parameter_conformance(
        &self,
        param: &Node,
        source: &str,
        declared_names: &HashSet<String>,
        has_size_t_param: bool,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(declarator) = param.child_by_field_name("declarator") {
            // Check for plain pointer parameters that could be conformant arrays
            if has_size_t_param && self.is_plain_pointer_param(param, &declarator, source) {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: "Pointer parameter should use conformant array syntax".to_string(),
                    file_path: String::new(),
                    line: declarator.start_position().row + 1,
                    column: declarator.start_position().column + 1,
                    suggestion: Some(
                        "Use conformant array parameter syntax (e.g., 'char p[n]') \
                        with the size parameter declared before the array"
                            .to_string(),
                    ),
                    ..Default::default()
                });
            }

            self.check_declarator_conformance(&declarator, source, declared_names, violations);
        }
    }

    fn is_plain_pointer_param(&self, param: &Node, declarator: &Node, source: &str) -> bool {
        // Check if this is a pointer type (char*, int*, etc.)
        if declarator.kind() == "pointer_declarator" {
            // Make sure it's not already an array or function pointer
            let has_array_or_func = self.has_nested_array_or_function(declarator);
            if !has_array_or_func {
                // Check if the type is char or similar (common buffer types)
                if let Some(type_node) = param.child_by_field_name("type") {
                    let type_text = get_node_text(&type_node, source);
                    // Only flag basic types that are commonly used as buffers
                    if type_text.contains("char")
                        || type_text.contains("void")
                        || type_text.contains("unsigned")
                        || type_text.contains("int")
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_nested_array_or_function(&self, node: &Node) -> bool {
        query::find_first_descendant(*node, |n| {
            n.kind() == "array_declarator" || n.kind() == "function_declarator"
        })
        .is_some()
    }

    fn check_declarator_conformance(
        &self,
        declarator: &Node,
        source: &str,
        declared_names: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if declarator.kind() == "array_declarator" {
            // Check if array size uses a variable
            if let Some(size_node) = declarator.child_by_field_name("size") {
                let size_text = get_node_text(&size_node, source).trim();

                // Check if size is a variable (identifier)
                if size_node.kind() == "identifier"
                    || (size_node.kind() == "subscript_expression"
                        && size_node.named_child_count() > 0
                        && size_node
                            .named_child(0)
                            .is_some_and(|n| n.kind() == "identifier"))
                {
                    // Extract variable name
                    let var_name = if size_node.kind() == "identifier" {
                        size_text.to_string()
                    } else if let Some(first_child) = size_node.named_child(0) {
                        get_node_text(&first_child, source).to_string()
                    } else {
                        return;
                    };

                    // Check if this variable was declared before this parameter
                    if !declared_names.contains(&var_name) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: format!(
                                "Array parameter uses size variable '{}' that is declared after the array parameter",
                                var_name
                            ),
                            file_path: String::new(),
                            line: declarator.start_position().row + 1,
                            column: declarator.start_position().column + 1,
                            suggestion: Some(format!(
                                "Declare size parameter '{}' before the array parameter, or use K&R style with semicolon",
                                var_name
                            )),
                            ..Default::default()
                        });
                    }
                }
            }
        } else if declarator.kind() == "pointer_declarator" {
            // Recurse to check nested declarators
            for i in 0..declarator.child_count() {
                if let Some(child) = declarator.child(i) {
                    self.check_declarator_conformance(&child, source, declared_names, violations);
                }
            }
        }
    }
}
