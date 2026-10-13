//! Shared AST-based array-declaration size resolution.
//!
//! Originated in ARR00-C to replace a text-scan approach for
//! out-of-bounds detection; promoted here so other rules with the
//! same "what size was this fixed array declared with" question — currently
//! STR31-C — can reuse it instead of re-implementing their own text/regex
//! scan. See `docs/design/str31c-arr00-migration-scoping.md`.

use crate::analyze::const_eval::{try_evaluate_expr, MacroConstantMap};
use crate::utility::cert_c::ast_utils::find_identifier_in_declarator;
use tree_sitter::Node;

/// Resolve an array's declared element count from its AST declaration.
///
/// Finds the `array_declarator` that declares `var_name` in the nearest block
/// scope enclosing `use_node`, then computes its size as
/// `max(evaluated-size-expression, initializer-element-count)`.
///
/// Returns `None` when the bound cannot be determined safely:
///   - the variable has no array declaration in scope,
///   - the explicit size expression is a non-constant we cannot evaluate
///     (e.g. a runtime expression or unknown macro), or
///   - a designated initializer is present without an evaluable explicit size.
///
/// Returning `None` suppresses the out-of-bounds check — the conservative,
/// false-positive-avoiding choice when the true bound is unknown.
pub fn resolve_declared_array_size(
    use_node: &Node,
    var_name: &str,
    source: &str,
    macros: &MacroConstantMap,
) -> Option<usize> {
    let arr_decl = find_array_declarator_in_scope(use_node, var_name, source)?;
    declared_size(&arr_decl, source, macros)
}

/// [`resolve_declared_array_size`] with the file scope answered from
/// `file`, an index of the file `use_node` belongs to built with the same
/// `macros`. Block scopes are still scanned; the file scope, which holds
/// every top-level declaration, is a lookup. Any other tree or text is
/// resolved by the scan.
pub fn resolve_declared_array_size_in_file(
    use_node: &Node,
    var_name: &str,
    source: &str,
    macros: &MacroConstantMap,
    file: &FileScopeArrays,
) -> Option<usize> {
    let before = use_node.start_byte();
    let mut scope = use_node.parent();
    while let Some(s) = scope {
        if s.parent().is_none() && file.is_of(&s, source) {
            let &(start, size) = file.first.get(var_name)?;
            return if start < before { size } else { None };
        }
        if let Some(found) = scan_block_declarators(&s, var_name, source, before) {
            return declared_size(&found, source, macros);
        }
        scope = s.parent();
    }
    None
}

/// For each name, the first `array_declarator` declaring it that the
/// file-scope scan can see, by start byte and declared size.
///
/// The scan of the root visits nodes in preorder, which is start-byte
/// order, and keeps to those starting before the use. So it finds the
/// first declarator of the name in the whole preorder when that one starts
/// before the use, and nothing otherwise: one lookup per use instead of a
/// pass over every top-level declaration before it.
#[derive(Debug, Default)]
pub struct FileScopeArrays {
    /// The root's node id and the text's address and length.
    of: (usize, usize, usize),
    first: std::collections::HashMap<String, (usize, Option<usize>)>,
}

impl FileScopeArrays {
    /// Index the file scope of `root`, the root of `source`'s tree.
    pub fn of(root: &Node, source: &str, macros: &MacroConstantMap) -> Self {
        let mut first = std::collections::HashMap::new();
        visit_scope_declarators(root, source, &mut |decl, name| {
            first
                .entry(name)
                .or_insert_with(|| (decl.start_byte(), declared_size(decl, source, macros)));
        });
        Self {
            of: (root.id(), source.as_ptr() as usize, source.len()),
            first,
        }
    }

    /// Whether this index was built from `root` of `source`.
    fn is_of(&self, root: &Node, source: &str) -> bool {
        self.of == (root.id(), source.as_ptr() as usize, source.len())
    }
}

/// Every `array_declarator` [`scan_block_declarators`] would test in
/// `scope`, in the order it tests them, with its declared name.
fn visit_scope_declarators<'a>(
    scope: &Node<'a>,
    source: &str,
    visit: &mut impl FnMut(&Node<'a>, String),
) {
    let mut cursor = scope.walk();
    for child in scope.children(&mut cursor) {
        if matches!(child.kind(), "compound_statement" | "function_definition") {
            continue;
        }
        if child.kind() == "array_declarator" {
            if let Some(name) = find_identifier_in_declarator(&child, source) {
                visit(&child, name);
            }
        }
        visit_scope_declarators(&child, source, visit);
    }
}

/// The element count `arr_decl` declares: `max(evaluated-size-expression,
/// initializer-element-count)`, or `None` when it cannot be determined (see
/// [`resolve_declared_array_size`]).
fn declared_size(arr_decl: &Node, source: &str, macros: &MacroConstantMap) -> Option<usize> {
    // Evaluate the explicit dimension expression, if any.
    let declared = match arr_decl.child_by_field_name("size") {
        Some(size_expr) => match try_evaluate_expr(&size_expr, source, macros) {
            Some(v) if v > 0 => Some(v as usize),
            // Size expression present but not a positive constant we can
            // evaluate -> bound unknown, do not flag.
            _ => return None,
        },
        // No explicit size (`arr[] = {...}`); rely on the initializer count.
        None => None,
    };

    // Count top-level initializer elements, if the declarator is initialized.
    let init_count = arr_decl
        .parent()
        .filter(|p| p.kind() == "init_declarator")
        .and_then(|p| p.child_by_field_name("value"))
        .filter(|v| v.kind() == "initializer_list")
        .and_then(|v| count_initializer_elements(&v));

    match (declared, init_count) {
        (Some(d), Some(c)) => Some(d.max(c)),
        (Some(d), None) => Some(d),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    }
}

/// Find the `array_declarator` that declares `var_name` and is visible at
/// `use_node`, honoring C block scoping: walk enclosing scopes innermost-first
/// so a block-local `tmp[4]` shadows a `tmp[3]` declared in a sibling block.
fn find_array_declarator_in_scope<'a>(
    use_node: &Node<'a>,
    var_name: &str,
    source: &str,
) -> Option<Node<'a>> {
    let before = use_node.start_byte();
    let mut scope = use_node.parent();
    while let Some(s) = scope {
        if let Some(found) = scan_block_declarators(&s, var_name, source, before) {
            return Some(found);
        }
        scope = s.parent();
    }
    None
}

/// Search one scope for an `array_declarator` of `var_name` declared textually
/// before byte offset `before`, without crossing into nested block scopes
/// (their declarations are not visible here).
///
/// Children are visited with a cursor, since `Node::child(i)` walks from the
/// first child each time, and the walk stops at the first child starting at
/// or after `before`: children are in source order and a node's descendants
/// never start before it, so nothing from there on can qualify. At file
/// scope that keeps a lookup from touching every later top-level declaration.
fn scan_block_declarators<'a>(
    scope: &Node<'a>,
    var_name: &str,
    source: &str,
    before: usize,
) -> Option<Node<'a>> {
    let mut cursor = scope.walk();
    for child in scope.children(&mut cursor) {
        if child.start_byte() >= before {
            break;
        }
        // A nested block / function body is a separate scope — skip it.
        if matches!(child.kind(), "compound_statement" | "function_definition") {
            continue;
        }
        if child.kind() == "array_declarator"
            && find_identifier_in_declarator(&child, source).as_deref() == Some(var_name)
        {
            return Some(child);
        }
        if let Some(found) = scan_block_declarators(&child, var_name, source, before) {
            return Some(found);
        }
    }
    None
}

/// Count top-level elements in an `initializer_list`.
///
/// Returns `None` if the list uses designated initializers (e.g. `[3] = x`),
/// where the element count does not bound the array size.
fn count_initializer_elements(list: &Node) -> Option<usize> {
    let mut count = 0;
    for i in 0..list.child_count() {
        if let Some(child) = list.child(i) {
            match child.kind() {
                "{" | "}" | "," | "comment" => {}
                // Designated initializer (`[idx] = v` or `.field = v`): the
                // element count does not bound the array size -> give up.
                "initializer_pair" => return None,
                _ => count += 1,
            }
        }
    }
    if count > 0 {
        Some(count)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::c_language;

    #[test]
    fn file_scope_index_agrees_with_the_scan() {
        let source = "#define N 8\nchar g[4];\nint h[N], *p;\n\
                      void f(char *in, int k[3]) { char g[16]; strcpy(g, in); use(h, k, late); }\n\
                      int late[2 * N];\nstruct s { char m[5]; } v[3];\n\
                      int f2(void) { { int g[7]; use(g); } use(g, late, m, v, w); return x[1]; }\n\
                      int w[] = {1, 2, 3}, g[99];\nint arr[2][9];\n\
                      void f3(void) { use(arr, w, g, unknown, n2); }\nint n2[n];\n";
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        let macros = crate::analyze::const_eval::collect_macro_constants(
            &root,
            source,
            crate::settings::IntFacts::default(),
        );
        let file = FileScopeArrays::of(&root, source, &macros);
        let mut uses = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier" {
                uses.push(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
        assert!(uses.len() > 30);
        for use_node in uses {
            for name in [
                "g", "h", "p", "in", "k", "late", "m", "v", "w", "arr", "n2", "x", "f",
            ] {
                assert_eq!(
                    resolve_declared_array_size_in_file(&use_node, name, source, &macros, &file),
                    resolve_declared_array_size(&use_node, name, source, &macros),
                    "{name:?} at byte {}",
                    use_node.start_byte()
                );
            }
        }
    }

    /// The scope scan as it was before it walked with a cursor and stopped
    /// at `before`: every child, by index, each declarator tested against
    /// `before` itself.
    fn scan_block_declarators_by_index<'a>(
        scope: &Node<'a>,
        var_name: &str,
        source: &str,
        before: usize,
    ) -> Option<Node<'a>> {
        for i in 0..scope.child_count() {
            if let Some(child) = scope.child(i) {
                if matches!(child.kind(), "compound_statement" | "function_definition") {
                    continue;
                }
                if child.kind() == "array_declarator"
                    && child.start_byte() < before
                    && find_identifier_in_declarator(&child, source).as_deref() == Some(var_name)
                {
                    return Some(child);
                }
                if let Some(found) =
                    scan_block_declarators_by_index(&child, var_name, source, before)
                {
                    return Some(found);
                }
            }
        }
        None
    }

    #[test]
    fn scope_scan_agrees_with_the_scan_by_index() {
        let source = "char g[4];\nint h[8], *p, q[2][3];\n\
                      void f(char *in, int k[3]) { char g[16]; { int g[7]; } int t[1], u[2]; }\n\
                      struct s { char m[5]; } v[3];\n\
                      int f2(void) { for (int i[2] = {0}; ; ) { char g[9]; } int late[4]; }\n\
                      int w[] = {1, 2, 3}, g[99];\n";
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut scopes = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            scopes.push(node);
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
        let names = [
            "g", "h", "p", "q", "in", "k", "t", "u", "m", "v", "i", "late", "w",
        ];
        for scope in scopes {
            for before in 0..=source.len() {
                for name in names {
                    assert_eq!(
                        scan_block_declarators(&scope, name, source, before).map(|n| n.id()),
                        scan_block_declarators_by_index(&scope, name, source, before)
                            .map(|n| n.id()),
                        "{name:?} in {} at byte {before}",
                        scope.kind()
                    );
                }
            }
        }
    }
}
