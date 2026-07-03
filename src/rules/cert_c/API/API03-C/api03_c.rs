//! API03-C: Create consistent interfaces and capabilities across related functions
//!
//! This rule detects inconsistent interfaces across related functions, particularly:
//! 1. Inconsistent parameter ordering between related functions
//! 2. Functions that manipulate parameter order via macros
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! // Inconsistent parameter ordering - FILE* in different positions
//! int fputs(const char * restrict s, FILE * restrict stream);
//! int fprintf(FILE * restrict stream, const char * restrict format, ...);
//! ```
//!
//! **Non-compliant (macro reversal):**
//! ```c
//! #define fputs(X,Y) fputs(Y,X)  // Reverses parameter order
//! ```
//!
//! **Compliant:**
//! ```c
//! // POSIX threads - consistent parameter ordering
//! int pthread_cond_init(pthread_cond_t * restrict, const pthread_condattr_t * restrict);
//! int pthread_mutex_init(pthread_mutex_t * restrict, const pthread_mutexattr_t * restrict);
//! int pthread_rwlock_init(pthread_rwlock_t * restrict, const pthread_rwlockattr_t * restrict);
//! ```
//!
//! ## Detection Strategy:
//! - Find function declarations with similar names (shared prefix)
//! - Check for FILE* or similar handle types in different parameter positions
//! - Detect macros that swap parameter order
//! - Report violations when inconsistencies are found

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Api03C;

impl CertRule for Api03C {
    fn rule_id(&self) -> &'static str {
        "API03-C"
    }

    fn description(&self) -> &'static str {
        "Create consistent interfaces and capabilities across related functions"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "API03-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Collect all function declarations
        let mut func_declarations = Vec::new();
        for decl in query::find_descendants_of_kind(*node, "declaration") {
            if let Some(func_info) = self.extract_function_info(&decl, source) {
                func_declarations.push(func_info);
            }
        }

        // Check for inconsistent parameter ordering between related functions
        self.check_related_functions(&func_declarations, source, &mut violations);

        // Check for macros that reverse parameter order
        self.check_macro_reversals(node, source, &mut violations);

        violations
    }
}

impl Api03C {
    #[allow(dead_code)]
    fn is_function_declaration(&self, decl_node: &Node) -> bool {
        // Look for function_declarator in the declaration
        let mut cursor = decl_node.walk();
        for child in decl_node.children(&mut cursor) {
            if child.kind() == "function_declarator" {
                return true;
            }
            // Check nested declarators
            if child.kind() == "init_declarator" {
                let mut inner_cursor = child.walk();
                for inner_child in child.children(&mut inner_cursor) {
                    if inner_child.kind() == "function_declarator" {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn check_related_functions(
        &self,
        declarations: &[FunctionInfo],
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Group functions by shared prefix
        let mut func_groups: HashMap<String, Vec<&FunctionInfo>> = HashMap::new();

        for func_info in declarations {
            // Extract prefix (e.g., "f" from "fputs", "fprintf")
            let prefix = self.get_function_prefix(&func_info.name);
            func_groups.entry(prefix).or_default().push(func_info);
        }

        // Check each group for inconsistent FILE* positioning
        for (prefix, funcs) in func_groups.iter() {
            if funcs.len() >= 2 && (prefix == "f" || prefix == "pthread") {
                self.check_file_handle_consistency(funcs, source, violations);
            }
        }
    }

    fn extract_function_info(&self, decl_node: &Node, source: &str) -> Option<FunctionInfo> {
        let mut cursor = decl_node.walk();

        for child in decl_node.children(&mut cursor) {
            if let Some(info) = self.extract_from_declarator(&child, source, decl_node) {
                return Some(info);
            }

            // Check init_declarator
            if child.kind() == "init_declarator" {
                let mut inner_cursor = child.walk();
                for inner_child in child.children(&mut inner_cursor) {
                    if let Some(info) =
                        self.extract_from_declarator(&inner_child, source, decl_node)
                    {
                        return Some(info);
                    }
                }
            }
        }

        None
    }

    fn extract_from_declarator(
        &self,
        node: &Node,
        source: &str,
        decl_node: &Node,
    ) -> Option<FunctionInfo> {
        if node.kind() != "function_declarator" {
            return None;
        }

        // Get function name
        let name = if let Some(declarator) = node.child_by_field_name("declarator") {
            get_node_text(&declarator, source)
        } else {
            return None;
        };

        // Get parameters
        let params = if let Some(params_node) = node.child_by_field_name("parameters") {
            self.extract_parameters(&params_node, source)
        } else {
            Vec::new()
        };

        Some(FunctionInfo {
            name: name.to_string(),
            params,
            line: decl_node.start_position().row + 1,
            column: decl_node.start_position().column + 1,
        })
    }

    fn extract_parameters(&self, params_node: &Node, source: &str) -> Vec<ParamInfo> {
        let mut params = Vec::new();
        let mut cursor = params_node.walk();

        for child in params_node.children(&mut cursor) {
            if child.kind() == "parameter_declaration" {
                if let Some(type_node) = child.child_by_field_name("type") {
                    let type_text = get_node_text(&type_node, source);
                    params.push(ParamInfo {
                        type_text: type_text.trim().to_string(),
                        position: params.len(),
                    });
                }
            }
        }

        params
    }

    fn get_function_prefix(&self, name: &str) -> String {
        // For functions like fputs, fprintf -> "f"
        // For pthread_mutex_init, pthread_cond_init -> "pthread"
        if name.starts_with("pthread_") {
            "pthread".to_string()
        } else if name.len() > 1 {
            name.chars().next().unwrap().to_string()
        } else {
            name.to_string()
        }
    }

    fn check_file_handle_consistency(
        &self,
        funcs: &[&FunctionInfo],
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Find FILE* positions in each function
        let mut file_positions: Vec<(usize, usize)> = Vec::new(); // (func_idx, param_position)

        for (func_idx, func) in funcs.iter().enumerate() {
            for (param_idx, param) in func.params.iter().enumerate() {
                if param.type_text.contains("FILE")
                    || param.type_text.contains("stream")
                    || (param.type_text.contains("*") && !param.type_text.contains("char"))
                {
                    file_positions.push((func_idx, param_idx));
                    break; // Only check first FILE* parameter
                }
            }
        }

        // Check if FILE* appears at different positions
        if file_positions.len() >= 2 {
            let first_pos = file_positions[0].1;
            for &(func_idx, param_pos) in &file_positions[1..] {
                if param_pos != first_pos {
                    // Found inconsistency!
                    let func1 = funcs[file_positions[0].0];
                    let func2 = funcs[func_idx];

                    self.report_inconsistent_ordering(
                        func1, func2, first_pos, param_pos, source, violations,
                    );
                }
            }
        }
    }

    fn report_inconsistent_ordering(
        &self,
        func1: &FunctionInfo,
        func2: &FunctionInfo,
        pos1: usize,
        pos2: usize,
        _source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::Medium,
            message: format!(
                "Inconsistent parameter ordering between related functions '{}' and '{}': FILE handle at position {} vs position {}",
                func1.name.trim(),
                func2.name.trim(),
                pos1 + 1,
                pos2 + 1
            ),
            file_path: String::new(),
            line: func2.line,
            column: func2.column,
            suggestion: Some(format!(
                "Ensure related functions use consistent parameter ordering. Consider placing FILE* handle in the same position for both '{}' and '{}'",
                func1.name.trim(),
                func2.name.trim()
            )),
            ..Default::default()
        });
    }

    fn check_macro_reversals(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for macro_node in query::find_descendants_of_kind(*node, "preproc_function_def") {
            self.check_macro_def(&macro_node, source, violations);
        }
    }

    fn check_macro_def(
        &self,
        macro_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get macro name
        let macro_name = if let Some(name_node) = macro_node.child_by_field_name("name") {
            get_node_text(&name_node, source)
        } else {
            return;
        };

        // Get macro parameters
        let mut params = Vec::new();
        if let Some(params_node) = macro_node.child_by_field_name("parameters") {
            let mut cursor = params_node.walk();
            for child in params_node.children(&mut cursor) {
                if child.kind() == "identifier" {
                    params.push(get_node_text(&child, source).to_string());
                }
            }
        }

        // Get macro value (body)
        let macro_value = if let Some(value_node) = macro_node.child_by_field_name("value") {
            get_node_text(&value_node, source)
        } else {
            return;
        };

        // Check if macro swaps parameters (e.g., #define fputs(X,Y) fputs(Y,X))
        if self.is_parameter_swap_with_params(macro_name, &params, macro_value) {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::Medium,
                message: format!(
                    "Macro '{}' reverses parameter order, creating inconsistent interface",
                    macro_name.trim()
                ),
                file_path: String::new(),
                line: macro_node.start_position().row + 1,
                column: macro_node.start_position().column + 1,
                suggestion: Some(
                    "Avoid macros that reorder parameters. Maintain consistent parameter ordering across related functions".to_string()
                ),
                ..Default::default()
            });
        }
    }

    fn is_parameter_swap_with_params(
        &self,
        macro_name: &str,
        params: &[String],
        macro_value: &str,
    ) -> bool {
        // Check if we have exactly 2 parameters
        if params.len() != 2 {
            return false;
        }

        // Check if the macro calls itself (e.g., fputs calls fputs)
        if !macro_value.contains(macro_name.trim()) {
            return false;
        }

        // Extract the parameter order in the macro body
        // Look for the function call in the body and check parameter order
        // e.g., "fputs(Y,X)" - we want to find Y and X in that order

        let param0 = &params[0];
        let param1 = &params[1];

        // Find positions of params in the macro value
        let pos0 = macro_value.find(param0.as_str());
        let pos1 = macro_value.find(param1.as_str());

        // If both parameters appear and param1 comes before param0, it's swapped
        if let (Some(p0), Some(p1)) = (pos0, pos1) {
            if p1 < p0 {
                return true;
            }
        }

        false
    }
}

#[derive(Debug)]
struct FunctionInfo {
    name: String,
    params: Vec<ParamInfo>,
    line: usize,
    column: usize,
}

#[derive(Debug)]
#[allow(dead_code)]
struct ParamInfo {
    type_text: String,
    position: usize,
}
