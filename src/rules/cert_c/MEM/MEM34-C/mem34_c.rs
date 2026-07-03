//! MEM34-C: Only free memory allocated dynamically
//!
//! This rule detects attempts to free or reallocate memory that was not dynamically allocated.
//!
//! ## Violations:
//! - Calling free() on a string literal pointer
//! - Calling free() on a stack-allocated variable
//! - Calling realloc() on a stack-allocated array
//! - Calling realloc() on a pointer to stack memory
//!
//! ## Compliant:
//! - Only free() memory returned from malloc/calloc/realloc
//! - Only realloc() memory that was previously dynamically allocated

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Mem34C;

impl CertRule for Mem34C {
    fn rule_id(&self) -> &'static str {
        "MEM34-C"
    }

    fn description(&self) -> &'static str {
        "Only free memory allocated dynamically"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MEM34-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Analyze each function independently
        for func_node in query::find_descendants_of_kind(*node, "function_definition") {
            let mut analyzer = MemorySourceAnalyzer::new();
            analyzer.analyze_function(&func_node, source, &mut violations);
        }

        violations
    }
}

struct MemorySourceAnalyzer {
    // Track which variables hold dynamically allocated memory
    dynamic_memory: HashSet<String>,
    // Track which variables hold non-dynamic memory (literals, stack arrays)
    non_dynamic_memory: HashMap<String, MemorySource>,
}

#[derive(Debug, Clone)]
enum MemorySource {
    StringLiteral(usize, usize), // line, column
    StackArray(usize, usize),    // line, column
}

impl MemorySourceAnalyzer {
    fn new() -> Self {
        Self {
            dynamic_memory: HashSet::new(),
            non_dynamic_memory: HashMap::new(),
        }
    }

    fn analyze_function(
        &mut self,
        func_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(body) = func_node.child_by_field_name("body") {
            // First pass: collect all variable sources
            self.collect_variable_sources(&body, source);

            // Second pass: check free/realloc calls
            self.check_free_calls(&body, source, violations);
        }
    }

    fn collect_variable_sources(&mut self, node: &Node, source: &str) {
        match node.kind() {
            "declaration" => {
                self.process_declaration(node, source);
            }
            "assignment_expression" => {
                self.process_assignment(node, source);
            }
            _ => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        self.collect_variable_sources(&child, source);
                    }
                }
            }
        }
    }

    fn process_declaration(&mut self, node: &Node, source: &str) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let declarator = if child.kind() == "init_declarator" {
                    child.child_by_field_name("declarator")
                } else if matches!(
                    child.kind(),
                    "array_declarator" | "pointer_declarator" | "identifier"
                ) {
                    Some(child)
                } else {
                    None
                };

                if let Some(declarator) = declarator {
                    let var_name = self.get_variable_name(&declarator, source);

                    // Check if it's a stack-allocated array
                    if declarator.kind() == "array_declarator" {
                        let pos = declarator.start_position();
                        self.non_dynamic_memory.insert(
                            var_name.clone(),
                            MemorySource::StackArray(pos.row + 1, pos.column + 1),
                        );
                    }

                    // Check initialization value (only for init_declarator)
                    if child.kind() == "init_declarator" {
                        if let Some(value) = child.child_by_field_name("value") {
                            self.classify_value(&var_name, &value, source);
                        }
                    }
                }
            }
        }
    }

    fn process_assignment(&mut self, node: &Node, source: &str) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            if left.kind() == "identifier" {
                let var_name = ast_utils::get_node_text_owned(&left, source);
                self.classify_value(&var_name, &right, source);
            }
        }
    }

    fn classify_value(&mut self, var_name: &str, value_node: &Node, source: &str) {
        if self.is_allocation_call(value_node, source) {
            // Dynamic allocation
            self.dynamic_memory.insert(var_name.to_string());
            self.non_dynamic_memory.remove(var_name);
        } else if value_node.kind() == "string_literal" {
            // String literal
            let pos = value_node.start_position();
            self.non_dynamic_memory.insert(
                var_name.to_string(),
                MemorySource::StringLiteral(pos.row + 1, pos.column + 1),
            );
            self.dynamic_memory.remove(var_name);
        } else if value_node.kind() == "identifier" {
            // Assignment from another variable - track the source
            let source_var = ast_utils::get_node_text_owned(value_node, source);
            if self.dynamic_memory.contains(&source_var) {
                self.dynamic_memory.insert(var_name.to_string());
                self.non_dynamic_memory.remove(var_name);
            } else if let Some(source_type) = self.non_dynamic_memory.get(&source_var) {
                self.non_dynamic_memory
                    .insert(var_name.to_string(), source_type.clone());
                self.dynamic_memory.remove(var_name);
            }
        }
    }

    fn check_free_calls(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call_node.child_by_field_name("function") {
                let func_name = ast_utils::get_node_text_owned(&function, source);

                if func_name == "free" {
                    self.check_free_argument(&call_node, source, violations);
                } else if func_name == "realloc" {
                    self.check_realloc_argument(&call_node, source, violations);
                }
            }
        }
    }

    fn check_free_argument(
        &self,
        call_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(arguments) = call_node.child_by_field_name("arguments") {
            for i in 0..arguments.child_count() {
                if let Some(arg) = arguments.child(i) {
                    if arg.kind() == "identifier" {
                        let var_name = ast_utils::get_node_text_owned(&arg, source);

                        // Check if this variable holds non-dynamic memory
                        if let Some(mem_source) = self.non_dynamic_memory.get(&var_name) {
                            let (line, column, source_type) = match mem_source {
                                MemorySource::StringLiteral(l, c) => (l, c, "string literal"),
                                MemorySource::StackArray(l, c) => (l, c, "stack-allocated array"),
                            };

                            violations.push(RuleViolation {
                                rule_id: "MEM34-C".to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Attempting to free() memory from {} '{}' which was not dynamically allocated",
                                    source_type, var_name
                                ),
                                file_path: String::new(),
                                line: *line,
                                column: *column,
                                suggestion: Some(
                                    "Only call free() on memory allocated with malloc/calloc/realloc".to_string()
                                ),
                                requires_manual_review: None,
                            });
                        }
                    }
                }
            }
        }
    }

    fn check_realloc_argument(
        &self,
        call_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(arguments) = call_node.child_by_field_name("arguments") {
            for i in 0..arguments.child_count() {
                if let Some(arg) = arguments.child(i) {
                    // Skip punctuation
                    if matches!(arg.kind(), "(" | ")" | ",") {
                        continue;
                    }

                    {
                        // Extract variable name from the first argument
                        let var_name = if arg.kind() == "identifier" {
                            ast_utils::get_node_text_owned(&arg, source)
                        } else {
                            // Might be a more complex expression, try to find identifier
                            self.find_identifier_in_expr(&arg, source)
                        };

                        if !var_name.is_empty() {
                            // Check if this variable holds non-dynamic memory
                            if let Some(mem_source) = self.non_dynamic_memory.get(&var_name) {
                                let (line, column, source_type) = match mem_source {
                                    MemorySource::StringLiteral(l, c) => (l, c, "string literal"),
                                    MemorySource::StackArray(l, c) => {
                                        (l, c, "stack-allocated array")
                                    }
                                };

                                violations.push(RuleViolation {
                                    rule_id: "MEM34-C".to_string(),
                                    severity: Severity::High,
                                    message: format!(
                                        "Attempting to realloc() memory from {} '{}' which was not dynamically allocated",
                                        source_type, var_name
                                    ),
                                    file_path: String::new(),
                                    line: *line,
                                    column: *column,
                                    suggestion: Some(
                                        "Only call realloc() on memory allocated with malloc/calloc/realloc".to_string()
                                    ),
                                    requires_manual_review: None,
                                });
                            }
                        }
                        break; // Only check first argument
                    }
                }
            }
        }
    }

    fn find_identifier_in_expr(&self, node: &Node, source: &str) -> String {
        query::find_first_descendant(*node, |n| n.kind() == "identifier")
            .map(|n| ast_utils::get_node_text_owned(&n, source))
            .unwrap_or_default()
    }

    fn is_allocation_call(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = ast_utils::get_node_text_owned(&function, source);
                return matches!(
                    func_name.as_str(),
                    "malloc" | "calloc" | "realloc" | "strdup" | "strndup" | "aligned_alloc"
                );
            }
        } else if node.kind() == "cast_expression" {
            // Handle casted allocations like (char*)malloc(...)
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if self.is_allocation_call(&child, source) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn get_variable_name(&self, declarator: &Node, source: &str) -> String {
        match declarator.kind() {
            "identifier" => ast_utils::get_node_text_owned(declarator, source),
            "pointer_declarator" | "array_declarator" => {
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if child.kind() == "identifier" {
                            return ast_utils::get_node_text_owned(&child, source);
                        }
                        let nested_name = self.get_variable_name(&child, source);
                        if nested_name != "unknown" {
                            return nested_name;
                        }
                    }
                }
                "unknown".to_string()
            }
            _ => "unknown".to_string(),
        }
    }
}
