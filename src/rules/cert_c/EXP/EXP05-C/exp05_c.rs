// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Exp05C;

impl CertRule for Exp05C {
    fn rule_id(&self) -> &'static str {
        "EXP05-C"
    }

    fn description(&self) -> &'static str {
        "Do not cast away a const qualification"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "EXP05-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check for explicit casts that remove const qualification
        for cast_node in query::find_descendants_of_kind(*node, "cast_expression") {
            if let Some(type_node) = cast_node.child_by_field_name("type") {
                if let Some(value_node) = cast_node.child_by_field_name("value") {
                    // Get the target type (what we're casting to)
                    let target_type = get_node_text(&type_node, source);

                    // Check if we're casting away const
                    // Target type should be a non-const pointer
                    if is_pointer_type(&target_type) && !target_type.contains("const") {
                        // Check if the value refers to a const-qualified variable
                        if is_value_const_qualified(&value_node, &cast_node, source) {
                            report_violation(&cast_node, source, &mut violations);
                        }
                    }
                }
            }
        }

        // Check for implicit const removal in function calls
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function_node) = call_node.child_by_field_name("function") {
                let function_name = get_node_text(&function_node, source);

                // Check known functions that take non-const pointers
                if is_modifying_function(function_name) {
                    if let Some(arguments) = call_node.child_by_field_name("arguments") {
                        check_function_arguments(
                            &arguments,
                            &call_node,
                            source,
                            function_name,
                            &mut violations,
                        );
                    }
                }
            }
        }

        violations
    }
}

/// Check if a type is a pointer type
fn is_pointer_type(type_str: &str) -> bool {
    type_str.contains('*')
}

/// Check if a value refers to a const-qualified variable/parameter
fn is_value_const_qualified(value_node: &Node, context: &Node, source: &str) -> bool {
    match value_node.kind() {
        "identifier" => {
            let id_name = get_node_text(value_node, source);
            // Search for the declaration in the function scope
            find_const_declaration(id_name, context, source)
        }
        _ => false,
    }
}

/// Extract the identifier a declarator ultimately declares, peeling off the
/// pointer/array/function/parenthesized wrappers around it — `*p[4]` yields
/// "p". The "declarator" field is followed first so an initializer or an
/// array-size expression is never mistaken for the declared name.
fn declarator_base_name(node: &Node, source: &str) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(get_node_text(node, source).to_string());
    }

    if let Some(inner) = node.child_by_field_name("declarator") {
        return declarator_base_name(&inner, source);
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(name) = declarator_base_name(&child, source) {
                return Some(name);
            }
        }
    }
    None
}

/// True if a declaration or parameter carries a `const` type qualifier.
/// Checked on the AST node rather than the declaration's raw text, which also
/// matches a `const` belonging to a cast in an initializer or to a type whose
/// name merely contains the word.
fn has_const_qualifier(node: &Node, source: &str) -> bool {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "type_qualifier" && get_node_text(&child, source) == "const" {
                return true;
            }
        }
    }
    false
}

/// Is the named identifier const-qualified where it is declared?
///
/// Resolution stops at the first scope that declares the name: a local or
/// parameter declaration SHADOWS a file-scope one, so a non-const local ends
/// the search at `false` instead of falling through to the global sweep.
/// Without that, any file-scope `const` whose name merely contained the
/// local's name answered for it — mbedtls's `aes_test_cfb128_iv` made every
/// local `iv` look const-qualified.
fn find_const_declaration(id_name: &str, context: &Node, source: &str) -> bool {
    // Find the containing function
    let mut current = Some(*context);
    while let Some(node) = current {
        if node.kind() == "function_definition" {
            // Parameters shadow file scope
            if let Some(declarator) = node.child_by_field_name("declarator") {
                if let Some(is_const) = find_param_declaration(&declarator, id_name, source) {
                    return is_const;
                }
            }

            // Then variable declarations in the function body
            if let Some(body) = node.child_by_field_name("body") {
                if let Some(is_const) = find_declaration(&body, id_name, source) {
                    return is_const;
                }
            }

            break;
        }
        current = node.parent();
    }

    // Only if nothing in function scope declared it: file-scope declarations
    if let Some(root) = get_translation_unit(context) {
        find_declaration(&root, id_name, source).unwrap_or(false)
    } else {
        false
    }
}

/// Get the translation unit (root) node
fn get_translation_unit<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    let mut current = Some(*node);
    while let Some(n) = current {
        if n.kind() == "translation_unit" {
            return Some(n);
        }
        current = n.parent();
    }
    None
}

/// Find the named identifier among a function declarator's parameters.
/// `Some(is_const)` if a parameter declares it, `None` if none does.
fn find_param_declaration(declarator: &Node, id_name: &str, source: &str) -> Option<bool> {
    for i in 0..declarator.child_count() {
        if let Some(child) = declarator.child(i) {
            if child.kind() == "parameter_list" {
                return find_in_param_list(&child, id_name, source);
            }
            // Recursively search in nested declarators
            if let Some(is_const) = find_param_declaration(&child, id_name, source) {
                return Some(is_const);
            }
        }
    }
    None
}

/// Find the named identifier in a parameter list. The parameter's declared
/// name must match exactly — a substring test made `const unsigned char *input`
/// answer for an unrelated `in`.
fn find_in_param_list(param_list: &Node, id_name: &str, source: &str) -> Option<bool> {
    for i in 0..param_list.child_count() {
        if let Some(param) = param_list.child(i) {
            if param.kind() == "parameter_declaration" {
                if let Some(declarator) = param.child_by_field_name("declarator") {
                    if declarator_base_name(&declarator, source).as_deref() == Some(id_name) {
                        return Some(has_const_qualifier(&param, source));
                    }
                }
            }
        }
    }
    None
}

/// Find the named identifier's declaration in a scope.
/// `Some(is_const)` if this scope declares it, `None` if it does not — the
/// caller needs that distinction to stop at a shadowing declaration rather
/// than continuing out to file scope.
fn find_declaration(body: &Node, id_name: &str, source: &str) -> Option<bool> {
    for i in 0..body.child_count() {
        if let Some(child) = body.child(i) {
            if child.kind() == "declaration" {
                // Match on AST structure, not raw text — raw text matching picks up
                // "const" from cast expressions inside initializers (e.g.,
                // `bool x = f((const T *)&servaddr)` contains "const" and "servaddr" but
                // servaddr is NOT const-declared).
                if let Some(is_const) = declaration_declares(&child, id_name, source) {
                    return Some(is_const);
                }
            }
            // Recursively search nested scopes, but NOT into other function
            // definitions — those have their own scope and their const parameters
            // don't apply here
            if child.kind() != "function_definition" {
                if let Some(is_const) = find_declaration(&child, id_name, source) {
                    return Some(is_const);
                }
            }
        }
    }
    None
}

/// Does this declaration declare the given variable, and if so is it const?
/// Only the type specifiers/qualifiers are consulted, never the initializer.
///
/// The declared name must match EXACTLY. Substring matching here is what let
/// a file-scope `static const unsigned char aes_test_cfb128_iv[16]` answer for
/// a local `iv`, and `static const int aes_test_ctr_len[3]` for a plain `len`.
fn declaration_declares(decl: &Node, id_name: &str, source: &str) -> Option<bool> {
    let mut declares = false;

    for i in 0..decl.child_count() {
        if let Some(child) = decl.child(i) {
            match child.kind() {
                "init_declarator"
                | "identifier"
                | "array_declarator"
                | "pointer_declarator"
                | "function_declarator"
                | "parenthesized_declarator"
                    if declarator_base_name(&child, source).as_deref() == Some(id_name) =>
                {
                    declares = true;
                }
                _ => {}
            }
        }
    }

    if declares {
        Some(has_const_qualifier(decl, source))
    } else {
        None
    }
}

/// Check if a function name is a known function that modifies its arguments
fn is_modifying_function(name: &str) -> bool {
    matches!(
        name,
        "memset"
            | "memcpy"
            | "memmove"
            | "strcpy"
            | "strncpy"
            | "strcat"
            | "strncat"
            | "sprintf"
            | "snprintf"
            | "gets"
            | "fgets"
            | "scanf"
            | "fscanf"
            | "sscanf"
    )
}

/// The argument positions (0-based) where a standard library function takes a
/// NON-const pointer. Passing a const-qualified object to one of those is what
/// casts const away; every other position is a size, a count, a const-qualified
/// formal or a format string, where a const argument is entirely correct.
///
/// Returns the fixed positions plus, for the scanf family, the first variadic
/// position — every vararg from there on is an output pointer.
///
/// This replaced an exemption list that named only memcpy/memmove's const
/// `src`, leaving size arguments eligible: `memcpy(buf, src, len)` reported
/// `len`, an int, as casting away const.
fn nonconst_pointer_positions(func_name: &str) -> (&'static [usize], Option<usize>) {
    match func_name {
        // memset(void *s, ...), memcpy/memmove(void *dst, const void *src, ...),
        // str*(char *dst, const char *src, ...), *printf(char *s, ...),
        // gets(char *s), fgets(char *s, int n, FILE *f)
        "memset" | "memcpy" | "memmove" | "strcpy" | "strncpy" | "strcat" | "strncat"
        | "sprintf" | "snprintf" | "gets" | "fgets" => (&[0], None),
        // scanf(const char *fmt, ...) — the varargs are the output pointers
        "scanf" => (&[], Some(1)),
        // fscanf(FILE *, const char *fmt, ...), sscanf(const char *s, const char *fmt, ...)
        "fscanf" | "sscanf" => (&[], Some(2)),
        _ => (&[], None),
    }
}

/// Check function arguments for const-qualified values
fn check_function_arguments(
    arguments: &Node,
    context: &Node,
    source: &str,
    func_name: &str,
    violations: &mut Vec<RuleViolation>,
) {
    let (fixed, variadic_start) = nonconst_pointer_positions(func_name);

    let mut arg_index = 0usize;
    for i in 0..arguments.child_count() {
        if let Some(arg) = arguments.child(i) {
            // Skip punctuation like commas and parentheses
            if arg.kind() == "," || arg.kind() == "(" || arg.kind() == ")" {
                continue;
            }

            // Only the non-const pointer positions can cast const away
            let takes_nonconst_pointer =
                fixed.contains(&arg_index) || matches!(variadic_start, Some(v) if arg_index >= v);

            if takes_nonconst_pointer {
                // Check if this argument is a const-qualified identifier
                if is_const_qualified_argument(&arg, context, source) {
                    report_violation(&arg, source, violations);
                    return; // Only report once per function call
                }
            }
            arg_index += 1;
        }
    }
}

/// Check if an argument is const-qualified
fn is_const_qualified_argument(node: &Node, context: &Node, source: &str) -> bool {
    match node.kind() {
        "identifier" => {
            let id_name = get_node_text(node, source);
            find_const_declaration(id_name, context, source)
        }
        // Field expressions (e.g., ptr->buffer): the base pointer may be const-qualified
        // but the member itself may not be. We can't determine member const-qualification
        // without struct definitions, so skip these to avoid false positives.
        "field_expression" => false,
        _ => {
            // Recursively check for identifiers in the argument
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if is_const_qualified_argument(&child, context, source) {
                        return true;
                    }
                }
            }
            false
        }
    }
}

/// Report a violation for casting away const
fn report_violation(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    let start_point = node.start_position();
    let node_text = get_node_text(node, source);

    violations.push(RuleViolation {
        rule_id: "EXP05-C".to_string(),
        severity: Severity::Medium,
        message: format!("Do not cast away const qualification: '{}'", node_text),
        file_path: String::new(),
        line: start_point.row + 1,
        column: start_point.column + 1,
        suggestion: Some(
            "Ensure const-qualified objects are not modified through cast-away pointers"
                .to_string(),
        ),
        ..Default::default()
    });
}
