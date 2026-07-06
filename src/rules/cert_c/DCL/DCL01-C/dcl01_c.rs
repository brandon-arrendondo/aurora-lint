use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Dcl01C;

impl CertRule for Dcl01C {
    fn rule_id(&self) -> &'static str {
        "DCL01-C"
    }

    fn description(&self) -> &'static str {
        "Do not reuse variable names in subscopes"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL01-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Collect all variable declarations at this level and check for shadowing
        check_scope_for_shadowing(node, source, &mut violations, self.rule_id());

        violations
    }
}

type Scope = HashMap<String, (usize, usize)>;

/// Check scopes for variable name shadowing, starting at `root`.
///
/// Uses an explicit work stack instead of recursion: an else-if chain nests
/// an `if_statement` as the `alternative` of the previous one, so a
/// generated/obfuscated chain thousands deep would blow the native call
/// stack if each link were a recursive call (the same hostap-style shape
/// that motivated task 153).
///
/// Each stack entry pairs a node with the scope of variable names visible
/// from its enclosing scopes (name -> declaration location); this mirrors
/// the `outer_vars` parameter the recursive version threaded through calls.
fn check_scope_for_shadowing(
    root: &Node,
    source: &str,
    violations: &mut Vec<RuleViolation>,
    rule_id: &str,
) {
    let mut stack: Vec<(Node, Scope)> = vec![(*root, Scope::new())];

    while let Some((node, outer_vars)) = stack.pop() {
        // Build a new scope with variables declared at this level
        let mut current_scope = outer_vars.clone();

        match node.kind() {
            "translation_unit" => check_translation_unit_shadowing(&node, source, &mut stack),
            "function_definition" => check_function_definition_shadowing(
                &node,
                source,
                &outer_vars,
                &mut current_scope,
                violations,
                rule_id,
                &mut stack,
            ),
            "compound_statement" => check_compound_statement_shadowing(
                &node,
                source,
                &outer_vars,
                &mut current_scope,
                violations,
                rule_id,
                &mut stack,
            ),
            "for_statement" => check_for_statement_shadowing(
                &node,
                source,
                &outer_vars,
                &current_scope,
                violations,
                rule_id,
                &mut stack,
            ),
            // While/do-while loop - check body
            "while_statement" | "do_statement" => {
                if let Some(body) = node.child_by_field_name("body") {
                    stack.push((body, current_scope));
                }
            }
            "if_statement" => check_if_statement_shadowing(&node, &current_scope, &mut stack),
            // Switch statement - check body
            "switch_statement" => {
                if let Some(body) = node.child_by_field_name("body") {
                    stack.push((body, current_scope));
                }
            }
            _ => {
                // For other nodes, queue children for processing
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        stack.push((child, current_scope.clone()));
                    }
                }
            }
        }
    }
}

/// `translation_unit` case of [`check_scope_for_shadowing`]: file scope
/// collects all global declarations, then queues each function body against
/// that global scope.
fn check_translation_unit_shadowing<'a>(
    node: &Node<'a>,
    source: &str,
    stack: &mut Vec<(Node<'a>, Scope)>,
) {
    let mut global_vars = HashMap::new();
    collect_declarations_in_node(node, source, &mut global_vars);

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "function_definition" {
                stack.push((child, global_vars.clone()));
            }
        }
    }
}

/// `function_definition` case of [`check_scope_for_shadowing`]: function
/// scope collects parameters (flagging any that shadow an outer variable),
/// then queues the function body.
#[allow(clippy::too_many_arguments)]
fn check_function_definition_shadowing<'a>(
    node: &Node<'a>,
    source: &str,
    outer_vars: &HashMap<String, (usize, usize)>,
    current_scope: &mut HashMap<String, (usize, usize)>,
    violations: &mut Vec<RuleViolation>,
    rule_id: &str,
    stack: &mut Vec<(Node<'a>, Scope)>,
) {
    let params = extract_function_parameters(node, source);
    for (param_name, line, col) in params {
        if let Some((outer_line, outer_col)) = outer_vars.get(&param_name) {
            violations.push(RuleViolation {
                rule_id: rule_id.to_string(),
                severity: Severity::Low,
                message: format!(
                    "Function parameter '{}' shadows variable from outer scope (line {}:{})",
                    param_name, outer_line, outer_col
                ),
                file_path: String::new(),
                line,
                column: col,
                suggestion: Some(format!(
                    "Rename parameter '{}' to avoid shadowing outer scope variable",
                    param_name
                )),
                ..Default::default()
            });
        }
        current_scope.insert(param_name, (line, col));
    }

    if let Some(body) = find_compound_statement(node) {
        stack.push((body, current_scope.clone()));
    }
}

/// `compound_statement` case of [`check_scope_for_shadowing`]: block scope
/// collects declarations in this block (flagging any that shadow an outer
/// variable), then queues nested scopes.
#[allow(clippy::too_many_arguments)]
fn check_compound_statement_shadowing<'a>(
    node: &Node<'a>,
    source: &str,
    outer_vars: &HashMap<String, (usize, usize)>,
    current_scope: &mut HashMap<String, (usize, usize)>,
    violations: &mut Vec<RuleViolation>,
    rule_id: &str,
    stack: &mut Vec<(Node<'a>, Scope)>,
) {
    let mut block_vars = HashMap::new();

    for i in 0..node.child_count() {
        let Some(child) = node.child(i) else { continue };
        if child.kind() != "declaration" {
            continue;
        }
        let decls = extract_declarations(&child, source);
        for (var_name, line, col) in decls {
            // Check if this shadows an outer variable
            if let Some((outer_line, outer_col)) = outer_vars.get(&var_name) {
                violations.push(RuleViolation {
                    rule_id: rule_id.to_string(),
                    severity: Severity::Low,
                    message: format!(
                        "Variable '{}' shadows variable from outer scope (line {}:{})",
                        var_name, outer_line, outer_col
                    ),
                    file_path: String::new(),
                    line,
                    column: col,
                    suggestion: Some(format!("Rename variable '{}' to avoid shadowing", var_name)),
                    ..Default::default()
                });
            }
            block_vars.insert(var_name, (line, col));
        }
    }

    // Merge block variables into current scope
    current_scope.extend(block_vars);

    // Queue nested scopes, in reverse so they're popped in original
    // left-to-right document order.
    for i in (0..node.child_count()).rev() {
        let Some(child) = node.child(i) else { continue };
        if matches!(
            child.kind(),
            "compound_statement"
                | "for_statement"
                | "while_statement"
                | "do_statement"
                | "if_statement"
                | "switch_statement"
        ) {
            stack.push((child, current_scope.clone()));
        }
    }
}

/// `for_statement` case of [`check_scope_for_shadowing`]: checks the
/// initializer for a loop-variable declaration that shadows an outer
/// variable, then queues the loop body.
#[allow(clippy::too_many_arguments)]
fn check_for_statement_shadowing<'a>(
    node: &Node<'a>,
    source: &str,
    outer_vars: &HashMap<String, (usize, usize)>,
    current_scope: &HashMap<String, (usize, usize)>,
    violations: &mut Vec<RuleViolation>,
    rule_id: &str,
    stack: &mut Vec<(Node<'a>, Scope)>,
) {
    let mut loop_scope = current_scope.clone();

    if let Some(init) = node.child_by_field_name("initializer") {
        if init.kind() == "declaration" {
            let decls = extract_declarations(&init, source);
            for (var_name, line, col) in decls {
                if let Some((outer_line, outer_col)) = outer_vars.get(&var_name) {
                    violations.push(RuleViolation {
                        rule_id: rule_id.to_string(),
                        severity: Severity::Low,
                        message: format!(
                            "Loop variable '{}' shadows variable from outer scope (line {}:{})",
                            var_name, outer_line, outer_col
                        ),
                        file_path: String::new(),
                        line,
                        column: col,
                        suggestion: Some(format!(
                            "Rename loop variable '{}' to avoid shadowing",
                            var_name
                        )),
                        ..Default::default()
                    });
                }
                loop_scope.insert(var_name, (line, col));
            }
        }
    }

    if let Some(body) = node.child_by_field_name("body") {
        stack.push((body, loop_scope));
    }
}

/// `if_statement` case of [`check_scope_for_shadowing`]: queues the
/// consequence and (if present) alternative branches. The alternative of an
/// `else if` is itself an `if_statement`, so a long else-if chain is
/// consumed one work-stack entry at a time rather than nesting a native
/// call per link.
fn check_if_statement_shadowing<'a>(
    node: &Node<'a>,
    current_scope: &HashMap<String, (usize, usize)>,
    stack: &mut Vec<(Node<'a>, Scope)>,
) {
    // Push alternative first so consequence (which appears first in source)
    // is popped and processed first.
    if let Some(alternative) = node.child_by_field_name("alternative") {
        stack.push((alternative, current_scope.clone()));
    }
    if let Some(consequence) = node.child_by_field_name("consequence") {
        stack.push((consequence, current_scope.clone()));
    }
}

/// Collect all variable declarations in a node (non-recursive)
fn collect_declarations_in_node(
    node: &Node,
    source: &str,
    vars: &mut HashMap<String, (usize, usize)>,
) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "declaration" {
                let decls = extract_declarations(&child, source);
                for (var_name, line, col) in decls {
                    vars.insert(var_name, (line, col));
                }
            }
        }
    }
}

/// Extract variable names from a declaration node
///
/// Returns: Vec<(variable_name, line_number, column_number)>
fn extract_declarations(decl_node: &Node, source: &str) -> Vec<(String, usize, usize)> {
    let mut declarations = Vec::new();

    // Look for declarators in the declaration
    for i in 0..decl_node.child_count() {
        if let Some(child) = decl_node.child(i) {
            match child.kind() {
                "init_declarator" => {
                    if let Some(declarator) = child.child_by_field_name("declarator") {
                        let var_name =
                            ast_utils::get_identifier_from_declarator(&declarator, source);
                        if !var_name.is_empty() {
                            let pos = declarator.start_position();
                            declarations.push((var_name, pos.row + 1, pos.column + 1));
                        }
                    }
                }
                "pointer_declarator" | "array_declarator" | "identifier" => {
                    let var_name = ast_utils::get_identifier_from_declarator(&child, source);
                    if !var_name.is_empty() {
                        let pos = child.start_position();
                        declarations.push((var_name, pos.row + 1, pos.column + 1));
                    }
                }
                _ => {}
            }
        }
    }

    declarations
}

/// Extract function parameters with their positions
///
/// Returns: Vec<(parameter_name, line_number, column_number)>
fn extract_function_parameters(func_node: &Node, source: &str) -> Vec<(String, usize, usize)> {
    let mut parameters = Vec::new();

    // Find the function_declarator
    for i in 0..func_node.child_count() {
        if let Some(child) = func_node.child(i) {
            if child.kind() == "function_declarator" {
                // Find parameter_list
                for j in 0..child.child_count() {
                    if let Some(param_list) = child.child(j) {
                        if param_list.kind() == "parameter_list" {
                            // Extract each parameter
                            for k in 0..param_list.child_count() {
                                if let Some(param) = param_list.child(k) {
                                    if param.kind() == "parameter_declaration" {
                                        // Find the declarator in the parameter
                                        for m in 0..param.child_count() {
                                            if let Some(declarator) = param.child(m) {
                                                if matches!(
                                                    declarator.kind(),
                                                    "identifier"
                                                        | "pointer_declarator"
                                                        | "array_declarator"
                                                        | "function_declarator"
                                                ) {
                                                    let param_name =
                                                        ast_utils::get_identifier_from_declarator(
                                                            &declarator,
                                                            source,
                                                        );
                                                    if !param_name.is_empty() {
                                                        let pos = declarator.start_position();
                                                        parameters.push((
                                                            param_name,
                                                            pos.row + 1,
                                                            pos.column + 1,
                                                        ));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    parameters
}

/// Find the compound_statement (body) of a function
fn find_compound_statement<'a>(func_node: &Node<'a>) -> Option<Node<'a>> {
    for i in 0..func_node.child_count() {
        if let Some(child) = func_node.child(i) {
            if child.kind() == "compound_statement" {
                return Some(child);
            }
        }
    }
    None
}
