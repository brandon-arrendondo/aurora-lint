// Declarator utilities for CERT C rules
// This module provides reusable functions for analyzing C declarators (arrays, pointers, function pointers)

use tree_sitter::Node;

// ============================================================================
// Declarator Type Checking
// ============================================================================

/// Check if a declarator contains a specific kind of declarator in its tree
/// This is the generic recursive function that powers all specific checks
///
/// # Arguments
/// * `node` - The declarator node to check
/// * `target_kind` - The kind of declarator to search for (e.g., "array_declarator", "pointer_declarator")
///
/// # Returns
/// `true` if the declarator tree contains a node of the target kind
///
/// # Examples
/// ```no_run
/// use aurora_lint::utility::cert_c::declarator_utils::has_declarator_of_kind;
/// use tree_sitter::Node;
/// // Check if field has array declarator:
/// // let declarator: Node = /* get from parsed AST */;
/// // if has_declarator_of_kind(&declarator, "array_declarator") {
/// //     // This is an array field
/// // }
/// ```
pub fn has_declarator_of_kind(node: &Node, target_kind: &str) -> bool {
    if node.kind() == target_kind {
        return true;
    }

    // Recursively check children
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if has_declarator_of_kind(&child, target_kind) {
                return true;
            }
        }
    }

    false
}

/// Check if a declarator is an array (has array_declarator)
///
/// # Examples
/// ```no_run
/// use aurora_lint::utility::cert_c::declarator_utils::is_array_declarator;
/// use tree_sitter::Node;
/// // int arr[10];      // returns true
/// // int *ptr;         // returns false
/// // int arr[5][10];   // returns true
/// ```
pub fn is_array_declarator(node: &Node) -> bool {
    has_declarator_of_kind(node, "array_declarator")
}

/// Check if a declarator is a pointer (has pointer_declarator)
///
/// # Examples
/// ```no_run
/// use aurora_lint::utility::cert_c::declarator_utils::is_pointer_declarator;
/// use tree_sitter::Node;
/// // int *ptr;         // returns true
/// // int **ptr;        // returns true
/// // int arr[10];      // returns false
/// ```
pub fn is_pointer_declarator(node: &Node) -> bool {
    has_declarator_of_kind(node, "pointer_declarator")
}

/// Check if a declarator is a function pointer (has function_declarator)
///
/// # Examples
/// ```no_run
/// use aurora_lint::utility::cert_c::declarator_utils::is_function_declarator;
/// use tree_sitter::Node;
/// // int (*fn)(int);   // returns true
/// // int *ptr;         // returns false
/// ```
pub fn is_function_declarator(node: &Node) -> bool {
    has_declarator_of_kind(node, "function_declarator")
}

// ============================================================================
// Typedef declarator chains
// ============================================================================

/// The declarator one level inside `n`. Pointer, array and function
/// declarators name it as the `declarator` field; a parenthesized declarator
/// has no field for it (`( declarator )`, possibly with an `ms_call_modifier`
/// first), so fall back to the first named child that is a declarator.
pub fn inner_declarator<'a>(n: &Node<'a>) -> Option<Node<'a>> {
    if let Some(d) = n.child_by_field_name("declarator") {
        return Some(d);
    }
    let mut cursor = n.walk();
    let found = n
        .named_children(&mut cursor)
        .find(|c| c.kind().ends_with("declarator") || c.kind() == "identifier");
    found
}

/// The declarators a `type_definition` binds: one per name, so
/// `typedef struct tagPOINT { ... } POINT, *LPPOINT;` yields both, and only
/// `*LPPOINT` is a pointer.
pub fn typedef_declarators<'a>(n: &Node<'a>) -> Vec<Node<'a>> {
    let mut cursor = n.walk();
    let found: Vec<Node<'a>> = n
        .children_by_field_name("declarator", &mut cursor)
        .collect();
    found
}

/// Does the typedef's specifier list carry `const` (the pointee is const)?
/// Only direct children count: a `const` inside a struct body or a parameter
/// list qualifies something else.
pub fn typedef_has_const_qualifier(n: &Node) -> bool {
    let mut cursor = n.walk();
    let found = n.named_children(&mut cursor).any(|c| {
        c.kind() == "type_qualifier" && {
            let mut inner = c.walk();
            let is_const = c.children(&mut inner).any(|k| k.kind() == "const");
            is_const
        }
    });
    found
}

/// What one typedef declarator chain spells, read from the outside in. Only
/// the chain is read -- never a struct body, whose pointer MEMBERS say nothing
/// about the type being named.
pub struct TypedefShape {
    /// The chain contains a `pointer_declarator`.
    pub is_pointer: bool,
    /// The chain contains a `function_declarator`: a function or function
    /// pointer type, which DCL05-C exempts.
    pub is_function: bool,
    /// The `type_identifier` at the end of the chain -- the name defined.
    pub name: Option<String>,
}

impl TypedefShape {
    /// Classify one declarator chain, starting at a `type_definition`'s
    /// `declarator` field.
    pub fn of(declarator: &Node, source: &str) -> Self {
        let mut shape = TypedefShape {
            is_pointer: false,
            is_function: false,
            name: None,
        };
        let mut cur = *declarator;
        loop {
            match cur.kind() {
                "pointer_declarator" => shape.is_pointer = true,
                "function_declarator" => shape.is_function = true,
                "type_identifier" | "identifier" => {
                    shape.name = Some(source[cur.byte_range()].to_string());
                    return shape;
                }
                _ => {}
            }
            match inner_declarator(&cur) {
                Some(next) => cur = next,
                None => return shape,
            }
        }
    }
}

/// The names a `type_definition` binds to a pointer type in DCL05-C's sense:
/// a pointer somewhere in the declarator chain, not a function pointer (CERT
/// exempts those), and not a pointer to const (`typedef const POINT
/// *LPCPOINT`, where `const` already sits on the pointee). Shared by the
/// rule, which flags such a typedef where it is written, and the prescan,
/// which records the names cross-file so `const LPPOINT pt` in another file
/// can be recognised for what it is. A typedef with an ERROR
/// among its own children (a calling-convention macro left unresolved) is
/// skipped; an ERROR inside a struct body is not held against the name.
pub fn pointer_typedef_names_in(type_definition: &Node, source: &str) -> Vec<String> {
    let mut cursor = type_definition.walk();
    let broken = type_definition.children(&mut cursor).any(|c| c.is_error());
    if broken || typedef_has_const_qualifier(type_definition) {
        return Vec::new();
    }
    typedef_declarators(type_definition)
        .into_iter()
        .filter(|d| !d.has_error())
        .map(|d| TypedefShape::of(&d, source))
        .filter(|shape| shape.is_pointer && !shape.is_function)
        .filter_map(|shape| shape.name)
        .collect()
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

    fn find_declarator<'a>(tree: &'a tree_sitter::Tree) -> Option<Node<'a>> {
        let root = tree.root_node();
        // Find first declarator in the tree
        for i in 0..root.child_count() {
            if let Some(child) = root.child(i) {
                if child.kind() == "declaration" {
                    if let Some(declarator) = child.child_by_field_name("declarator") {
                        return Some(declarator);
                    }
                }
            }
        }
        None
    }

    #[test]
    fn test_is_array_declarator() {
        let tree = parse_c_code("int arr[10];");
        let declarator = find_declarator(&tree).unwrap();
        assert!(is_array_declarator(&declarator));
    }

    #[test]
    fn test_is_pointer_declarator() {
        let tree = parse_c_code("int *ptr;");
        let declarator = find_declarator(&tree).unwrap();
        assert!(is_pointer_declarator(&declarator));
    }

    #[test]
    fn test_is_not_array() {
        let tree = parse_c_code("int *ptr;");
        let declarator = find_declarator(&tree).unwrap();
        assert!(!is_array_declarator(&declarator));
    }

    #[test]
    fn test_is_not_pointer() {
        let tree = parse_c_code("int arr[10];");
        let declarator = find_declarator(&tree).unwrap();
        assert!(!is_pointer_declarator(&declarator));
    }

    #[test]
    fn test_multidimensional_array() {
        let tree = parse_c_code("int arr[5][10];");
        let declarator = find_declarator(&tree).unwrap();
        assert!(is_array_declarator(&declarator));
    }

    #[test]
    fn test_double_pointer() {
        let tree = parse_c_code("int **ptr;");
        let declarator = find_declarator(&tree).unwrap();
        assert!(is_pointer_declarator(&declarator));
    }
}
