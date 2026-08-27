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

/// The C23 / GCC extended floating types: the ISO/IEC TS 18661 interchange
/// (`_FloatN`, `_DecimalN`) and extended (`_FloatNx`, `_DecimalNx`) formats,
/// plus GCC's non-standard spellings (`__float128`, `__fp16`, `__bf16`).
///
/// Every spelling here begins with `_` + uppercase or with `__`, which C
/// reserves to the implementation, so a token matching one of these is always
/// the implementation's floating type and never a user typedef — safe to
/// match without further qualification.
///
/// Shared with FLP38-C, which needs the same set but as an *exact* whole-type
/// match rather than a token scan (see `Flp38C::is_floating_type`).
pub const EXTENDED_FLOAT_TYPES: &[&str] = &[
    "_Float16",
    "_Float32",
    "_Float32x",
    "_Float64",
    "_Float64x",
    "_Float128",
    "_Float128x",
    "_Decimal32",
    "_Decimal64",
    "_Decimal64x",
    "_Decimal128",
    "_Decimal128x",
    "__float128",
    "__fp16",
    "__bf16",
];

/// True if a type string denotes a floating-point type: `float`, `double`,
/// `long double`, `float_t`, `double_t`, or any of [`EXTENDED_FLOAT_TYPES`].
///
/// Matches whole type *tokens* — never substrings — so integer typedefs whose
/// names merely embed "float"/"double" (e.g. `double_buffered_count`) are NOT
/// misclassified as float (which would suppress a real integer finding).
pub fn is_float_type(type_str: &str) -> bool {
    type_str
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|tok| {
            matches!(tok, "float" | "double" | "float_t" | "double_t")
                || EXTENDED_FLOAT_TYPES.contains(&tok)
        })
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
        if let Some(name) = extract_identifier_name(&declarator, source) {
            let full_type = if is_pointer_declarator_field(&declarator) {
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
                    if let Some(name) = extract_identifier_name(&decl, source) {
                        let full_type = if is_pointer_declarator_field(&decl) {
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

/// True if this declarator (or an `init_declarator` wrapping it) contains a
/// `pointer_declarator`. The `init_declarator` unwrap matters because a
/// `declaration` node's `declarator` field IS the `init_declarator` itself
/// when there's an initializer (e.g. `float *p = get_ptr();`), not a bare
/// `pointer_declarator` -- a case this function's direct-kind-check
/// predecessor missed, silently recording such a variable as non-pointer
/// (the same bug task 490 fixed in INT32-C's equivalent helper).
fn is_pointer_declarator_field(node: &Node) -> bool {
    if node.kind() == "pointer_declarator" {
        return true;
    }
    if node.kind() == "init_declarator" {
        if let Some(decl) = node.child_by_field_name("declarator") {
            return decl.kind() == "pointer_declarator";
        }
    }
    false
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

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_c_code(code: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let language = crate::parser::c_language();
        parser.set_language(&language).unwrap();
        parser.parse(code, None).unwrap()
    }

    #[test]
    fn is_float_type_is_word_boundary_aware() {
        assert!(is_float_type("float"));
        assert!(is_float_type("double"));
        assert!(!is_float_type("double_buffered_count"));
    }

    #[test]
    fn is_float_type_covers_c23_extended_float_types() {
        for t in EXTENDED_FLOAT_TYPES {
            assert!(is_float_type(t), "{t} should classify as floating-point");
        }
        assert!(is_float_type("const _Decimal64"));
        // Word-boundary discipline still holds for the extended spellings: a
        // longer identifier that merely starts with one is a single token.
        assert!(!is_float_type("_Float32_count"));
        assert!(!is_float_type("my_Float64"));
    }

    #[test]
    fn collect_variable_types_records_multi_token_and_extended_float_types() {
        // tree-sitter-c emits `long double` as ONE sized_type_specifier node,
        // so extract_type_and_name's overwrite-per-specifier loop does not
        // truncate it to "long" -- the concern raised by task 502 when
        // comparing against FLP38-C's token-concatenating declared_type_text.
        // The extended types parse as type_identifier and survive too.
        let src = "void f(void) { long double a; _Float32 b; _Decimal64 c; }";
        let tree = parse_c_code(src);
        let func = tree
            .root_node()
            .child(0)
            .expect("function_definition child");
        let type_map = collect_variable_types(&func, src);
        assert_eq!(type_map.get("a").map(|s| s.as_str()), Some("long double"));
        assert_eq!(type_map.get("b").map(|s| s.as_str()), Some("_Float32"));
        assert_eq!(type_map.get("c").map(|s| s.as_str()), Some("_Decimal64"));
        for name in ["a", "b", "c"] {
            assert!(is_float_type(type_map.get(name).unwrap()), "{name}");
        }
    }

    #[test]
    fn collect_variable_types_marks_init_declarator_pointer() {
        // Regression test for the same init_declarator-unwrap bug task 490
        // fixed in overflow_helpers.rs: a single declarator with an
        // initializer (`declarator` field IS the init_declarator itself)
        // must still be recorded as a pointer type.
        let src = "void f(void) { float *p = get_ptr(); }";
        let tree = parse_c_code(src);
        let func = tree
            .root_node()
            .child(0)
            .expect("function_definition child");
        let type_map = collect_variable_types(&func, src);
        assert_eq!(type_map.get("p").map(|s| s.as_str()), Some("float *"));
    }
}
