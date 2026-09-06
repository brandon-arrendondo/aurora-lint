// SPDX-License-Identifier: Apache-2.0
//! Best-effort pointer-type inference for the integer-hazard CERT-C rules.
//!
//! INT00-C (unguarded unsigned subtraction), INT30-C (unsigned wrap), INT31-C
//! (narrowing conversion) and INT32-C (signed overflow) each detect a hazard
//! of *integer* arithmetic. `ptr + int` is pointer arithmetic -- well defined
//! and bounded by the pointee object -- and `ptr - ptr` is a `ptrdiff_t`
//! computation; neither wraps, overflows or narrows the way the integer
//! expression of the same shape does. Out-of-bounds pointer formation is
//! ARR30-C's concern, not theirs.
//!
//! Each of those rules classified an operand's type from its own map and each
//! independently lost the pointer, so `buf += readnb` read as a narrowing
//! assignment into `unsigned char` and `prot + prot_len - icv_len` as an
//! unsigned subtraction (task 914). The classification lives here once.
//!
//! The inference is deliberately one-directional: an expression is reported
//! pointer-typed only when *positively* determined to be one, so an operand
//! whose type does not resolve stays non-pointer and the rules keep their
//! recall. Every caller uses the answer to SUPPRESS, never to fire.

use crate::analyze::argument_objects::declared_pointers;
use crate::utility::cert_c::ast_utils;
use crate::utility::cert_c::float_typing::StructFieldTypes;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

/// The pointer-typed names a translation unit puts in scope that a
/// function-local type map cannot know about: its file-scope variables and its
/// pointer-returning functions.
///
/// Built once per file. Both sets are keyed by name alone, which is all the
/// callers ask of them -- a name resolves against the rule's own type map
/// first, so a local or parameter always shadows a file-scope entry of the
/// same name.
#[derive(Debug, Default, Clone)]
pub struct PointerFacts {
    /// File-scope variables declared with a pointer or array declarator.
    /// Arrays belong here: `buf + n` on `static char buf[N]` is pointer
    /// arithmetic exactly as it is on `static char *buf`.
    file_scope_pointers: HashSet<String>,
    /// Functions this translation unit declares or defines as returning a
    /// pointer, so a call to one can be recognized as a pointer operand
    /// (`wpabuf_head_u8(resp) + start`).
    pointer_returning_functions: HashSet<String>,
}

impl PointerFacts {
    /// Collect the file-scope pointer facts of one parsed translation unit.
    pub fn collect(root: &Node, source: &str) -> Self {
        let mut facts = Self::default();
        for decl in ast_utils::file_scope_descendants_of_kinds(*root, &["declaration"]) {
            // A prototype is a `declaration` whose declarator is a
            // `function_declarator` wrapped in a `pointer_declarator`:
            // `unsigned char *wpabuf_head_u8(struct wpabuf *buf);`
            let returns_pointer = pointer_returning_declarator_name(&decl, source);
            for declared in declared_pointers(&decl, source) {
                // That prototype has a `pointer_declarator` too, so it also
                // reaches `declared_pointers` -- but it declares a FUNCTION,
                // not a pointer variable of the same name.
                if returns_pointer.as_deref() == Some(declared.name.as_str()) {
                    continue;
                }
                facts.file_scope_pointers.insert(declared.name);
            }
            if let Some(name) = returns_pointer {
                facts.pointer_returning_functions.insert(name);
            }
        }
        for func in query::find_descendants_of_kind(*root, "function_definition") {
            if let Some(name) = pointer_returning_declarator_name(&func, source) {
                facts.pointer_returning_functions.insert(name);
            }
        }
        facts
    }
}

/// The function name bound by `node`'s declarator when that declarator is a
/// `function_declarator` nested inside a `pointer_declarator` -- i.e. the
/// declared function returns a pointer. `None` for anything else, including a
/// pointer *variable* declaration.
fn pointer_returning_declarator_name(node: &Node, source: &str) -> Option<String> {
    let declarator = node.child_by_field_name("declarator")?;
    if declarator.kind() != "pointer_declarator" {
        return None;
    }
    let mut inner = declarator.child_by_field_name("declarator")?;
    // `char **strsplit(...)` nests one pointer_declarator inside another.
    while inner.kind() == "pointer_declarator" {
        inner = inner.child_by_field_name("declarator")?;
    }
    if inner.kind() != "function_declarator" {
        return None;
    }
    let name = ast_utils::get_identifier_from_declarator(&inner, source);
    (!name.is_empty()).then_some(name)
}

/// True only when `node`'s value is *positively* determined to have pointer
/// type.
///
/// `type_map` is the caller's own `{name -> type}` map (pointer types spelled
/// with a trailing `*`, as [`overflow_helpers::collect_variable_types`] and
/// [`ast_utils::resolve_field_expression_type`] produce them);
/// `struct_field_types` resolves member access; `facts` covers the file-scope
/// names no function-local map holds.
///
/// [`overflow_helpers::collect_variable_types`]: crate::utility::cert_c::overflow_helpers::collect_variable_types
pub fn expr_is_pointer(
    node: &Node,
    source: &str,
    type_map: &std::collections::HashMap<String, String>,
    struct_field_types: &StructFieldTypes,
    facts: &PointerFacts,
) -> bool {
    match node.kind() {
        "identifier" => {
            let name = ast_utils::get_node_text(node, source);
            match type_map.get(name) {
                Some(t) => ast_utils::is_pointer_type(t),
                // Not a local or parameter: a file-scope declaration is the
                // remaining way this name can be in scope here.
                None => facts.file_scope_pointers.contains(name),
            }
        }
        "field_expression" => {
            ast_utils::resolve_field_expression_type(node, source, type_map, struct_field_types)
                .is_some_and(|t| ast_utils::is_pointer_type(&t))
        }
        "cast_expression" => match node.child_by_field_name("type") {
            // An explicit cast states the expression's type outright, in
            // either direction: `(uintptr_t)p` is an integer and `(char *)n`
            // is a pointer.
            Some(t) => ast_utils::is_pointer_type(ast_utils::get_node_text(&t, source)),
            None => false,
        },
        "parenthesized_expression" => node
            .named_child(0)
            .is_some_and(|c| expr_is_pointer(&c, source, type_map, struct_field_types, facts)),
        "call_expression" => match node.child_by_field_name("function") {
            Some(f) => facts
                .pointer_returning_functions
                .contains(ast_utils::get_node_text(&f, source).trim()),
            None => false,
        },
        // A string literal is an array of char, so `"abc" + 1` is pointer
        // arithmetic.
        "string_literal" | "concatenated_string" => true,
        "pointer_expression" => {
            // `&x` yields a pointer. `*p` yields the pointee, whose type this
            // module does not track -- left non-pointer, per the
            // positive-determination rule above.
            matches!(operator_text(node, source).as_deref(), Some("&"))
        }
        "binary_expression" => {
            let Some(op) = operator_text(node, source) else {
                return false;
            };
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return false;
            };
            let left_ptr = expr_is_pointer(&left, source, type_map, struct_field_types, facts);
            let right_ptr = expr_is_pointer(&right, source, type_map, struct_field_types, facts);
            match op.as_str() {
                // `ptr + int` (either order) is a pointer; `ptr + ptr` is not C.
                "+" => left_ptr != right_ptr,
                // `ptr - int` is a pointer, but `ptr - ptr` is a ptrdiff_t.
                "-" => left_ptr && !right_ptr,
                _ => false,
            }
        }
        _ => false,
    }
}

/// True when `node` is *pointer* arithmetic rather than integer arithmetic:
/// either its value is a pointer (`ptr + int`, `ptr - int`) or a pointer
/// participates in it (`ptr - ptr`, whose `ptrdiff_t` result is bounded by the
/// pointee object).
///
/// This is the predicate the integer-hazard rules gate on. It recurses through
/// `+`/`-` chains, so `prot + prot_len - icv_len` is recognized whole, and
/// through parentheses -- but NOT through a cast, because a cast to an integer
/// type is the programmer stating an integer value of known width, which those
/// rules should keep checking.
///
/// For an `assignment_expression` both sides are examined, which is what
/// catches the compound forms (`buf += readnb`, `pos_len += pos - orig_pos`).
pub fn is_pointer_arithmetic(
    node: &Node,
    source: &str,
    type_map: &std::collections::HashMap<String, String>,
    struct_field_types: &StructFieldTypes,
    facts: &PointerFacts,
) -> bool {
    if expr_is_pointer(node, source, type_map, struct_field_types, facts) {
        return true;
    }
    let recurse = |n: &Node| is_pointer_arithmetic(n, source, type_map, struct_field_types, facts);
    match node.kind() {
        "binary_expression" => {
            if !matches!(
                operator_text(node, source).as_deref(),
                Some("+") | Some("-")
            ) {
                return false;
            }
            node.child_by_field_name("left")
                .is_some_and(|l| recurse(&l))
                || node
                    .child_by_field_name("right")
                    .is_some_and(|r| recurse(&r))
        }
        "assignment_expression" => {
            node.child_by_field_name("left")
                .is_some_and(|l| recurse(&l))
                || node
                    .child_by_field_name("right")
                    .is_some_and(|r| recurse(&r))
        }
        "parenthesized_expression" => node.named_child(0).is_some_and(|c| recurse(&c)),
        _ => false,
    }
}

/// The text of `node`'s `operator` field, trimmed.
fn operator_text(node: &Node, source: &str) -> Option<String> {
    let op = node.child_by_field_name("operator")?;
    Some(ast_utils::get_node_text(&op, source).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn parse_c_code(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let language = crate::parser::c_language();
        parser.set_language(&language).unwrap();
        parser.parse(code, None).unwrap()
    }

    /// Classify the single expression in `int f(void) { return <expr>; }`.
    fn classify(expr_src: &str, types: &[(&str, &str)]) -> (bool, bool) {
        let code = format!("int f(void) {{ return {}; }}", expr_src);
        let tree = parse_c_code(&code);
        let root = tree.root_node();
        let expr = query::find_descendants_of_kind(root, "return_statement")
            .first()
            .and_then(|r| r.named_child(0))
            .expect("no expression parsed");
        let type_map: HashMap<String, String> = types
            .iter()
            .map(|(n, t)| (n.to_string(), t.to_string()))
            .collect();
        let sft = StructFieldTypes::new();
        let facts = PointerFacts::default();
        (
            expr_is_pointer(&expr, &code, &type_map, &sft, &facts),
            is_pointer_arithmetic(&expr, &code, &type_map, &sft, &facts),
        )
    }

    const PTR: &[(&str, &str)] = &[
        ("p", "unsigned char *"),
        ("q", "unsigned char *"),
        ("n", "size_t"),
        ("m", "size_t"),
    ];

    #[test]
    fn pointer_plus_integer_is_a_pointer() {
        assert_eq!(classify("p + n", PTR), (true, true));
        assert_eq!(classify("n + p", PTR), (true, true));
        assert_eq!(classify("p - n", PTR), (true, true));
    }

    #[test]
    fn pointer_difference_is_not_a_pointer_but_is_pointer_arithmetic() {
        // `p - q` has ptrdiff_t type, so it is not itself a pointer -- but a
        // rule looking for integer wrap must still keep its hands off it.
        assert_eq!(classify("p - q", PTR), (false, true));
    }

    #[test]
    fn integer_arithmetic_stays_integer() {
        assert_eq!(classify("n + m", PTR), (false, false));
        assert_eq!(classify("n - m", PTR), (false, false));
    }

    #[test]
    fn chained_pointer_arithmetic_is_recognized_whole() {
        // hostap eap_eke_common.c:663 -- parses as `(p + n) - m`.
        assert_eq!(classify("p + n - m", PTR), (true, true));
    }

    #[test]
    fn multiplication_of_a_pointer_difference_stays_checkable() {
        // The gate recurses through `+`/`-` only: scaling a pointer
        // difference is integer arithmetic that can still overflow.
        assert_eq!(classify("(p - q) * n", PTR), (false, false));
    }

    #[test]
    fn cast_states_the_type_in_both_directions() {
        assert!(classify("(char *)n", PTR).0);
        // An explicit cast to an integer type is the programmer stating an
        // integer value of known width; the rules should keep checking it.
        assert_eq!(classify("(size_t)p", PTR), (false, false));
    }

    #[test]
    fn address_of_is_a_pointer_but_a_dereference_is_not_assumed() {
        assert!(classify("&n", PTR).0);
        // `*pp` yields the pointee, whose type this module does not track.
        assert!(!classify("*p", PTR).0);
    }

    #[test]
    fn unresolved_operands_stay_non_pointer() {
        // Positive determination only: an unknown name must not suppress.
        assert_eq!(classify("unknown + other", &[]), (false, false));
    }

    #[test]
    fn file_scope_pointers_and_pointer_returning_calls_resolve() {
        let code = "static char *resolved_path;\n\
                    unsigned char *head_u8(void *b);\n\
                    int f(void) { return 0; }";
        let tree = parse_c_code(code);
        let facts = PointerFacts::collect(&tree.root_node(), code);
        assert!(facts.file_scope_pointers.contains("resolved_path"));
        assert!(facts.pointer_returning_functions.contains("head_u8"));
        // A pointer-returning prototype is not also a pointer variable.
        assert!(!facts.file_scope_pointers.contains("head_u8"));
    }

    #[test]
    fn a_local_shadows_a_file_scope_pointer_of_the_same_name() {
        let code = "static char *buf;\nint f(void) { return 0; }";
        let tree = parse_c_code(code);
        let facts = PointerFacts::collect(&tree.root_node(), code);
        let expr_code = "int f(void) { return buf + 1; }";
        let expr_tree = parse_c_code(expr_code);
        let expr = query::find_descendants_of_kind(expr_tree.root_node(), "return_statement")
            .first()
            .and_then(|r| r.named_child(0))
            .unwrap();
        let sft = StructFieldTypes::new();

        let mut shadowed = HashMap::new();
        shadowed.insert("buf".to_string(), "int".to_string());
        assert!(!expr_is_pointer(&expr, expr_code, &shadowed, &sft, &facts));
        assert!(expr_is_pointer(
            &expr,
            expr_code,
            &HashMap::new(),
            &sft,
            &facts
        ));
    }
}
