use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Dcl17C;

impl CertRule for Dcl17C {
    fn rule_id(&self) -> &'static str {
        "DCL17-C"
    }

    fn description(&self) -> &'static str {
        "Beware of miscompiled volatile-qualified variables"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL17-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Only check at translation unit level (root node)
        if node.kind() != "translation_unit" {
            return violations;
        }

        // Pass 1: Collect all volatile variable names
        let volatile_vars = collect_volatile_variables(node, source);

        // Pass 2: Find direct accesses to volatile variables
        find_direct_volatile_accesses(node, source, &volatile_vars, &mut violations);

        // Pass 3: Detect K&R-style function declarations and definitions
        find_kr_style_functions(node, source, &mut violations);

        violations
    }
}

/// Collects names of all volatile-qualified variables declared in the file
fn collect_volatile_variables<'a>(root: &Node, source: &'a str) -> HashSet<&'a str> {
    let mut volatile_vars = HashSet::new();
    let mut cursor = root.walk();

    // Walk through all declarations in translation unit
    for child in root.children(&mut cursor) {
        if child.kind() == "declaration" {
            if has_volatile_qualifier(&child, source) {
                // Extract variable name(s) from this declaration
                collect_declarator_names(&child, source, &mut volatile_vars);
            }
        }
    }

    volatile_vars
}

/// Checks if a declaration has the volatile qualifier
fn has_volatile_qualifier(decl_node: &Node, source: &str) -> bool {
    let mut cursor = decl_node.walk();
    for child in decl_node.children(&mut cursor) {
        if child.kind() == "type_qualifier" {
            let text = ast_utils::get_node_text(&child, source);
            if text == "volatile" {
                return true;
            }
        }
        // Also check within storage_class_specifier or type_specifier
        if child.kind() == "storage_class_specifier" || child.kind() == "primitive_type" {
            if has_volatile_qualifier(&child, source) {
                return true;
            }
        }
    }
    false
}

/// Extracts variable names from declarators in a declaration
fn collect_declarator_names<'a>(decl_node: &Node, source: &'a str, names: &mut HashSet<&'a str>) {
    let mut cursor = decl_node.walk();
    for child in decl_node.children(&mut cursor) {
        match child.kind() {
            "init_declarator" => {
                if let Some(declarator) = child.child_by_field_name("declarator") {
                    if let Some(name) = extract_identifier_name(&declarator, source) {
                        names.insert(name);
                    }
                }
            }
            "identifier" => {
                let name = ast_utils::get_node_text(&child, source);
                names.insert(name);
            }
            "pointer_declarator" => {
                if let Some(name) = extract_identifier_name(&child, source) {
                    names.insert(name);
                }
            }
            _ => {}
        }
    }
}

/// Extracts the identifier name from a declarator node
fn extract_identifier_name<'a>(declarator: &Node, source: &'a str) -> Option<&'a str> {
    match declarator.kind() {
        "identifier" => Some(ast_utils::get_node_text(declarator, source)),
        "pointer_declarator" | "array_declarator" | "function_declarator" => {
            if let Some(child_declarator) = declarator.child_by_field_name("declarator") {
                extract_identifier_name(&child_declarator, source)
            } else {
                // Try to find identifier child
                let mut cursor = declarator.walk();
                for child in declarator.children(&mut cursor) {
                    if child.kind() == "identifier" {
                        return Some(ast_utils::get_node_text(&child, source));
                    }
                    if let Some(name) = extract_identifier_name(&child, source) {
                        return Some(name);
                    }
                }
                None
            }
        }
        _ => None,
    }
}

/// Finds all direct accesses to volatile variables (not wrapped in function calls)
fn find_direct_volatile_accesses(
    node: &Node,
    source: &str,
    volatile_vars: &HashSet<&str>,
    violations: &mut Vec<RuleViolation>,
) {
    for n in query::find_descendants_of_kind(*node, "identifier") {
        let var_name = ast_utils::get_node_text(&n, source);

        if volatile_vars.contains(var_name) {
            // Check if this is a direct access (not wrapped in function call)
            if is_direct_access(&n, source) {
                // Skip simple volatile reads and writes — these are well-defined
                // on all modern compilers. Only flag compound operations (++, --,
                // +=, -=, etc.) where read-modify-write may be non-atomic or
                // subject to optimization issues.
                if is_simple_volatile_access(&n) {
                    // Simple read or simple assignment — safe, skip
                } else {
                    let start_point = n.start_position();
                    violations.push(RuleViolation {
                        rule_id: "DCL17-C".to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "Direct access to volatile variable '{}' may be miscompiled. Wrap volatile accesses in functions",
                            var_name
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Use wrapper functions: int vol_read(volatile int *p) { return *p; }".to_string()
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }
}

/// Returns true if the volatile variable is accessed in a simple read or write
/// context — these are well-defined and safe.  Compound operations (++, --,
/// +=, -=, etc.) and multi-access expressions are NOT simple.
fn is_simple_volatile_access(node: &Node) -> bool {
    if let Some(parent) = node.parent() {
        match parent.kind() {
            // Simple write: `vol_var = expr;` or simple read: `x = vol_var;`
            // tree-sitter uses "assignment_expression" only for plain `=`.
            // Compound assignments (+=, -=, etc.) are "augmented_assignment_expression".
            "assignment_expression" => {
                return true;
            }
            // Simple read in init declarator: `int x = vol_var;`
            "init_declarator" => return true,
            // Simple read in return: `return vol_var;`
            "return_statement" => return true,
            // Simple read in condition: `if (vol_var)`, `while (vol_var)`
            "parenthesized_expression" => {
                if let Some(grandparent) = parent.parent() {
                    if matches!(
                        grandparent.kind(),
                        "if_statement" | "while_statement" | "for_statement"
                    ) {
                        return true;
                    }
                }
            }
            // Argument to function call: `func(vol_var)` — simple read
            "argument_list" => return true,
            _ => {}
        }
    }
    false
}

/// Determines if an identifier access is "direct" (not wrapped in a function call)
fn is_direct_access(node: &Node, _source: &str) -> bool {
    // Walk up to find the context
    let mut current = node.parent();

    while let Some(parent) = current {
        match parent.kind() {
            // If we're taking the address of the variable (&var), this might be for a wrapper
            "unary_expression" => {
                if let Some(operator) = parent.child_by_field_name("operator") {
                    if operator.kind() == "&" {
                        // Check if this address-of is being passed to a function
                        if let Some(grandparent) = parent.parent() {
                            if grandparent.kind() == "argument_list" {
                                // &var is passed to function - this is wrapped access (compliant)
                                return false;
                            }
                        }
                    }
                }
                // Dereference (*ptr) is direct access
                current = parent.parent();
            }

            // If we're in a function call argument list, check if we're the function name
            // or an argument
            "call_expression" => {
                // Check if our node is the function being called
                if let Some(function) = parent.child_by_field_name("function") {
                    if is_ancestor_of(&function, node) {
                        // We ARE the function name, not an argument - direct access
                        return true;
                    }
                }
                // We're an argument to a function call - NOT direct access
                return false;
            }

            // These contexts indicate direct access
            "assignment_expression"
            | "update_expression"
            | "binary_expression"
            | "init_declarator"
            | "return_statement"
            | "for_statement"
            | "while_statement"
            | "if_statement"
            | "switch_statement" => {
                return true;
            }

            // Pointer dereference expression
            "pointer_expression" => {
                // Check if this is dereferencing a function call result
                if let Some(argument) = parent.child_by_field_name("argument") {
                    if argument.kind() == "call_expression" {
                        // *func() - func returns a pointer, dereferencing it
                        return false;
                    }
                }
                current = parent.parent();
            }

            _ => {
                current = parent.parent();
            }
        }
    }

    // Default: if we reached root without finding a clear context, consider it direct
    false
}

/// Checks if `ancestor` is an ancestor of `descendant` in the tree
fn is_ancestor_of(ancestor: &Node, descendant: &Node) -> bool {
    let mut current = Some(*descendant);
    while let Some(node) = current {
        if node.id() == ancestor.id() {
            return true;
        }
        current = node.parent();
    }
    false
}

/// Detect K&R-style function declarations and definitions.
///
/// Flags two patterns:
/// 1. Empty parameter list in declarations: `int func();` (should be `int func(void);`)
/// 2. K&R-style function definitions where parameter types are listed after the
///    declarator: `void func(x) int x; { ... }`
fn find_kr_style_functions(root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            "declaration" => {
                // Check for empty parameter list in function declarations
                check_empty_param_list_decl(&child, source, violations);
            }
            "function_definition" => {
                // Check for K&R-style definition (declaration nodes between
                // function_declarator and compound_statement)
                check_kr_style_definition(&child, source, violations);
            }
            _ => {}
        }
    }
}

/// Check if a declaration has a function_declarator with empty parameter list.
/// `int func();` has parameter_list with only ( and ) — no parameter_declaration
/// and no `void`. `int func(void);` has a parameter_declaration with `void`.
fn check_empty_param_list_decl(decl: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    let mut decl_cursor = decl.walk();
    for child in decl.children(&mut decl_cursor) {
        if child.kind() == "function_declarator" {
            if let Some(params) = child.child_by_field_name("parameters") {
                if is_empty_param_list(&params) {
                    let func_name = if let Some(id) = child.child_by_field_name("declarator") {
                        ast_utils::get_node_text(&id, source)
                    } else {
                        // Try to find identifier directly
                        find_func_name_in_declarator(&child, source)
                    };
                    violations.push(RuleViolation {
                        rule_id: "DCL17-C".to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "Function '{}' declared with empty parameter list (K&R style). \
                             Use '(void)' for functions that accept no arguments.",
                            func_name
                        ),
                        file_path: String::new(),
                        line: child.start_position().row + 1,
                        column: child.start_position().column + 1,
                        suggestion: Some(format!(
                            "Change '{}()' to '{}(void)' to declare a proper prototype",
                            func_name, func_name,
                        )),
                        ..Default::default()
                    });
                }
            }
        }
    }
}

/// Find the function name identifier within a function_declarator node.
fn find_func_name_in_declarator<'a>(func_decl: &Node<'a>, source: &'a str) -> &'a str {
    for i in 0..func_decl.child_count() {
        if let Some(child) = func_decl.child(i) {
            if child.kind() == "identifier" {
                return ast_utils::get_node_text(&child, source);
            }
        }
    }
    "unknown"
}

/// Returns true if the parameter_list contains no parameter_declaration nodes.
fn is_empty_param_list(params: &Node) -> bool {
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if child.kind() == "parameter_declaration" {
            return false;
        }
        // Also check for bare identifiers (K&R param names)
        if child.kind() == "identifier" {
            return false;
        }
    }
    true
}

/// Check for K&R-style function definitions where tree-sitter places
/// `declaration` nodes as direct children of `function_definition`
/// (between the function_declarator and compound_statement).
fn check_kr_style_definition(func_def: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    let mut has_kr_params = false;
    let mut func_name = "unknown";

    let mut cursor = func_def.walk();
    for child in func_def.children(&mut cursor) {
        if child.kind() == "function_declarator" {
            func_name = find_func_name_in_declarator(&child, source);
        }
        // A `declaration` as direct child of function_definition (not inside
        // compound_statement) indicates K&R parameter declarations
        if child.kind() == "declaration" {
            has_kr_params = true;
        }
    }

    if has_kr_params {
        violations.push(RuleViolation {
            rule_id: "DCL17-C".to_string(),
            severity: Severity::Medium,
            message: format!(
                "Function '{}' uses K&R-style (old-style) parameter declarations. \
                 Use modern prototype syntax.",
                func_name,
            ),
            file_path: String::new(),
            line: func_def.start_position().row + 1,
            column: func_def.start_position().column + 1,
            suggestion: Some(
                "Rewrite using prototype syntax: void func(int x) instead of void func(x) int x;"
                    .to_string(),
            ),
            ..Default::default()
        });
    }
}
