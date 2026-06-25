// SPDX-License-Identifier: Apache-2.0
//! Best-effort floating-point type inference for CERT-C rules.
//!
//! Shared by rules that must distinguish integer arithmetic from floating-point
//! arithmetic via the C usual arithmetic conversions (e.g. INT33-C integer
//! divide-by-zero, FLP06-C integer-arithmetic-in-float-initializer). The
//! inference is intentionally conservative: an expression is reported as float
//! only when *positively* determined to be `float`/`double`, so unknown
//! expressions stay non-float and integer-focused detection keeps its recall.

use crate::utility::cert_c::ast_utils;
use std::collections::HashMap;
use tree_sitter::Node;

/// Map of `struct/typedef name -> { field name -> field type }`.
pub type StructFieldTypes = HashMap<String, HashMap<String, String>>;

/// True if a type string denotes a floating-point type (`float`, `double`,
/// `long double`, `float_t`, `double_t`).
///
/// Matches whole type *tokens* — never substrings — so integer typedefs whose
/// names merely embed "float"/"double" (e.g. `double_buffered_count`) are NOT
/// misclassified as float (which would suppress a real integer finding).
pub fn is_float_type(type_str: &str) -> bool {
    type_str
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|tok| matches!(tok, "float" | "double" | "float_t" | "double_t"))
}

/// True if a numeric literal is a floating-point constant: contains a `.`, an
/// exponent, or an `f`/`F` suffix. Hexadecimal integer literals (`0x1F`) are
/// excluded even though they may end in `f`/`F`.
pub fn is_float_literal(text: &str) -> bool {
    let t = text.trim();
    if t.starts_with("0x") || t.starts_with("0X") {
        // Hex float (C99 `0x1p4`) uses 'p'/'P' exponent; otherwise integer.
        return t.contains('p') || t.contains('P');
    }
    t.contains('.') || t.contains('e') || t.contains('E') || t.ends_with('f') || t.ends_with('F')
}

/// Best-effort: does this expression have floating-point type? Returns true only
/// when positively determined to be float/double; unknown expressions return
/// false so integer-focused detection (and recall) is preserved.
///
/// `type_map` is a `name -> type` map for the enclosing function (see
/// [`collect_variable_types`]); `struct_field_types` resolves field accesses
/// (`v.x`) and may be empty when no project context is available.
pub fn expr_is_float(
    node: &Node,
    source: &str,
    type_map: &HashMap<String, String>,
    struct_field_types: &StructFieldTypes,
) -> bool {
    match node.kind() {
        "number_literal" => is_float_literal(ast_utils::get_node_text(node, source)),
        "identifier" => {
            let name = ast_utils::get_node_text(node, source);
            type_map
                .get(name)
                .map(|t| is_float_type(t))
                .unwrap_or(false)
        }
        "field_expression" => {
            ast_utils::resolve_field_expression_type(node, source, type_map, struct_field_types)
                .map(|t| is_float_type(&t))
                .unwrap_or(false)
        }
        "cast_expression" => {
            // `(double)x` — the cast type determines the operand's type.
            if let Some(t) = node.child_by_field_name("type") {
                is_float_type(ast_utils::get_node_text(&t, source))
            } else if let Some(v) = node.child_by_field_name("value") {
                expr_is_float(&v, source, type_map, struct_field_types)
            } else {
                false
            }
        }
        "parenthesized_expression" => node
            .named_child(0)
            .map(|c| expr_is_float(&c, source, type_map, struct_field_types))
            .unwrap_or(false),
        "unary_expression" | "pointer_expression" => node
            .child_by_field_name("argument")
            .map(|a| expr_is_float(&a, source, type_map, struct_field_types))
            .unwrap_or(false),
        "binary_expression" => {
            // Usual arithmetic conversions: float if either operand is float.
            let l = node
                .child_by_field_name("left")
                .map(|n| expr_is_float(&n, source, type_map, struct_field_types))
                .unwrap_or(false);
            let r = node
                .child_by_field_name("right")
                .map(|n| expr_is_float(&n, source, type_map, struct_field_types))
                .unwrap_or(false);
            l || r
        }
        _ => false,
    }
}

/// Best-effort dual of [`expr_is_float`]: true only when the expression is
/// *provably* integer-typed — every leaf is an integer literal or a known
/// non-float, non-pointer typed identifier. Unknown operands (function calls,
/// unresolved identifiers, struct fields, casts, subscripts) yield false, so a
/// caller that fires on "integer arithmetic" stays conservative and does not
/// misfire on float-returning calls (`sinf`/`cosf`) or unresolved types.
pub fn expr_is_definitely_integer(
    node: &Node,
    source: &str,
    type_map: &HashMap<String, String>,
) -> bool {
    match node.kind() {
        "number_literal" => !is_float_literal(ast_utils::get_node_text(node, source)),
        "identifier" => {
            let name = ast_utils::get_node_text(node, source);
            match type_map.get(name) {
                Some(t) => !is_float_type(t) && !t.contains('*'),
                None => false,
            }
        }
        "parenthesized_expression" => node
            .named_child(0)
            .map(|c| expr_is_definitely_integer(&c, source, type_map))
            .unwrap_or(false),
        "unary_expression" => node
            .child_by_field_name("argument")
            .map(|a| expr_is_definitely_integer(&a, source, type_map))
            .unwrap_or(false),
        "binary_expression" => {
            let l = node
                .child_by_field_name("left")
                .map(|n| expr_is_definitely_integer(&n, source, type_map))
                .unwrap_or(false);
            let r = node
                .child_by_field_name("right")
                .map(|n| expr_is_definitely_integer(&n, source, type_map))
                .unwrap_or(false);
            l && r
        }
        _ => false,
    }
}

/// Build a `name -> type` map for the parameters and local declarations of a
/// `function_definition` node.
pub fn collect_variable_types(node: &Node, source: &str) -> HashMap<String, String> {
    let mut type_map = HashMap::new();
    if node.kind() == "function_definition" {
        if let Some(declarator) = node.child_by_field_name("declarator") {
            collect_params_from_declarator(&declarator, source, &mut type_map);
        }
        if let Some(body) = node.child_by_field_name("body") {
            collect_local_declarations(&body, source, &mut type_map);
        }
    }
    type_map
}

fn collect_params_from_declarator(
    node: &Node,
    source: &str,
    type_map: &mut HashMap<String, String>,
) {
    if node.kind() == "function_declarator" {
        if let Some(params) = node.child_by_field_name("parameters") {
            for i in 0..params.child_count() {
                if let Some(param) = params.child(i) {
                    if param.kind() == "parameter_declaration" {
                        extract_type_and_name(&param, source, type_map);
                    }
                }
            }
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_params_from_declarator(&child, source, type_map);
        }
    }
}

fn collect_local_declarations(node: &Node, source: &str, type_map: &mut HashMap<String, String>) {
    if node.kind() == "declaration" {
        extract_type_and_name(node, source, type_map);
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_local_declarations(&child, source, type_map);
        }
    }
}

fn extract_type_and_name(node: &Node, source: &str, type_map: &mut HashMap<String, String>) {
    let mut type_text = String::new();
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "primitive_type"
                | "sized_type_specifier"
                | "type_identifier"
                | "struct_specifier" => {
                    type_text = ast_utils::get_node_text(&child, source).to_string();
                }
                _ => {}
            }
        }
    }
    if type_text.is_empty() {
        return;
    }

    if let Some(declarator) = node.child_by_field_name("declarator") {
        let is_pointer = declarator.kind() == "pointer_declarator";
        if let Some(name) = extract_identifier_name(&declarator, source) {
            let full_type = if is_pointer {
                format!("{} *", type_text)
            } else {
                type_text.clone()
            };
            type_map.insert(name, full_type);
        }
    }

    // `int a, b;` style init_declarator lists
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "init_declarator" {
                if let Some(decl) = child.child_by_field_name("declarator") {
                    let is_pointer = decl.kind() == "pointer_declarator";
                    if let Some(name) = extract_identifier_name(&decl, source) {
                        let full_type = if is_pointer {
                            format!("{} *", type_text)
                        } else {
                            type_text.clone()
                        };
                        type_map.insert(name, full_type);
                    }
                }
            }
        }
    }
}

fn extract_identifier_name(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" => Some(ast_utils::get_node_text(node, source).to_string()),
        "pointer_declarator" | "array_declarator" | "parenthesized_declarator" => node
            .child_by_field_name("declarator")
            .and_then(|inner| extract_identifier_name(&inner, source)),
        _ => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" {
                        return Some(ast_utils::get_node_text(&child, source).to_string());
                    }
                }
            }
            None
        }
    }
}
