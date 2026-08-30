use crate::utility::cert_c::ast_utils::{get_node_text, is_dereference_expression};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use tree_sitter::Node;

/// A structurally-canonical lvalue: a bare variable, or a field access
/// rooted in one. Unifies every source spelling of the same storage
/// location — `p->buf`, `(*p).buf`, `((p))->buf` — into one value, instead
/// of the literal-source-text keying used elsewhere in this codebase (e.g.
/// MEM30-C's `check_field_access`/`process_free_call`), where two spellings
/// of the same field are two different dictionary keys.
///
/// Array subscripts are deliberately NOT index-sensitive: `arr[i]` and
/// `arr[j]` both collapse to the identity of `arr` (matching the existing
/// `extract_base_variable`/`is_write_through_param` behavior, which already
/// discards the index and recurses on the base). Only struct/union field
/// access is field-sensitive.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LValue {
    /// A bare identifier's canonical text (e.g. "p").
    Var(String),
    /// A field access on some base lvalue (e.g. `Field(Var("p"), "buf")` for
    /// both `p->buf` and `(*p).buf`). `Rc` rather than `Box` because
    /// `BranchState::fork`/`restore` (MEM30-C) clone `HashSet<LValue>`s on
    /// every if/else branch — with `Box` that walks and re-allocates the
    /// whole field chain per clone; `Rc` makes it a refcount bump.
    Field(Rc<LValue>, String),
}

impl LValue {
    /// The innermost `Var` name — the storage-identity root, discarding all
    /// field structure. Needed because some existing tracking (union-member
    /// aliasing on free, realloc relationships) is deliberately
    /// base-variable-scoped rather than field-sensitive, and must stay that
    /// way.
    pub fn root_var(&self) -> &str {
        match self {
            LValue::Var(name) => name,
            LValue::Field(base, _) => base.root_var(),
        }
    }

    /// True if this is a field access rather than a bare variable.
    pub fn is_field(&self) -> bool {
        matches!(self, LValue::Field(..))
    }
}

/// Parse an expression node into its canonical `LValue`, unwrapping
/// deref/field/subscript/parenthesized/cast spellings. Returns `None` for
/// anything that isn't a variable/field-access chain (call results,
/// literals, binary expressions, etc.) — callers treat `None` as "not a
/// trackable storage location".
pub fn lvalue_of(node: &Node, source: &str) -> Option<LValue> {
    match node.kind() {
        "identifier" => Some(LValue::Var(get_node_text(node, source).to_string())),
        "field_expression" => {
            let base_node = node.child_by_field_name("argument")?;
            let base = lvalue_of(&base_node, source)?;
            let field_node = node.child_by_field_name("field")?;
            let field_name = get_node_text(&field_node, source).to_string();
            Some(LValue::Field(Rc::new(base), field_name))
        }
        // *p and &p both parse as pointer_expression in this grammar; both
        // are a pure identity-preserving unwrap for our purposes.
        "pointer_expression" | "subscript_expression" => {
            let base_node = node.child_by_field_name("argument")?;
            lvalue_of(&base_node, source)
        }
        "parenthesized_expression" => {
            for i in 0..node.child_count() {
                let child = node.child(i)?;
                if child.kind() != "(" && child.kind() != ")" {
                    return lvalue_of(&child, source);
                }
            }
            None
        }
        "cast_expression" => {
            let value = node.child_by_field_name("value")?;
            lvalue_of(&value, source)
        }
        _ => None,
    }
}

/// Same traversal as [`lvalue_of`], additionally reporting whether
/// unwrapping crossed a pointer *dereference* (`*p`) as opposed to a pure
/// address-of (`&p`) or a subscript/paren/cast unwrap. `lvalue_of` treats
/// `*p` and `&p` identically (both parse as `pointer_expression` in this
/// grammar, and both are "identity-preserving" for canonical-storage
/// purposes) -- but a caller that cares whether the resulting `LValue` is
/// reached *through* a pointer (e.g. an ownership rule that must not
/// conflate freeing `p` with freeing `*p`) needs that bit, hence a second
/// entry point rather than baking it into `LValue`'s own `Eq`/`Hash` shape
/// (task 584), which every existing `AliasMap`/`HashSet<LValue>` caller
/// relies on to collapse structurally-identical storage locations.
#[allow(dead_code)]
pub fn lvalue_of_crossing_deref(node: &Node, source: &str) -> Option<(LValue, bool)> {
    fn walk(node: &Node, source: &str, crossed: &mut bool) -> Option<LValue> {
        match node.kind() {
            "identifier" => Some(LValue::Var(get_node_text(node, source).to_string())),
            "field_expression" => {
                let base_node = node.child_by_field_name("argument")?;
                let base = walk(&base_node, source, crossed)?;
                let field_node = node.child_by_field_name("field")?;
                let field_name = get_node_text(&field_node, source).to_string();
                Some(LValue::Field(Rc::new(base), field_name))
            }
            "pointer_expression" => {
                if is_dereference_expression(node, source) {
                    *crossed = true;
                }
                let base_node = node.child_by_field_name("argument")?;
                walk(&base_node, source, crossed)
            }
            "subscript_expression" => {
                let base_node = node.child_by_field_name("argument")?;
                walk(&base_node, source, crossed)
            }
            "parenthesized_expression" => {
                for i in 0..node.child_count() {
                    let child = node.child(i)?;
                    if child.kind() != "(" && child.kind() != ")" {
                        return walk(&child, source, crossed);
                    }
                }
                None
            }
            "cast_expression" => {
                let value = node.child_by_field_name("value")?;
                walk(&value, source, crossed)
            }
            _ => None,
        }
    }
    let mut crossed = false;
    let lv = walk(node, source, &mut crossed)?;
    Some((lv, crossed))
}

/// Single-hop alias table: `alias -> target`.
pub type AliasMap = HashMap<LValue, LValue>;

/// Follow an alias chain to its canonical target, with cycle protection.
pub fn resolve_canonical(map: &AliasMap, lv: &LValue) -> LValue {
    let mut current = lv.clone();
    let mut visited: HashSet<LValue> = HashSet::new();
    while let Some(target) = map.get(&current) {
        if visited.contains(target) {
            break;
        }
        visited.insert(current.clone());
        current = target.clone();
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::CParser;

    fn parse_expr(src: &str) -> (tree_sitter::Tree, String) {
        let source = format!("void f(void) {{ {} }}", src);
        let mut parser = CParser::new().expect("parser");
        let tree = parser.parse_source(&source).expect("parse");
        (tree, source)
    }

    fn first_expr_node<'a>(tree: &'a tree_sitter::Tree, source: &str, kind: &str) -> Node<'a> {
        fn find<'a>(node: Node<'a>, kind: &str, source: &str) -> Option<Node<'a>> {
            if node.kind() == kind {
                // Skip the outer "f(void)" pieces by preferring the last
                // matching node (the actual expression under test, since the
                // function signature contributes no matches for our kinds).
                return Some(node);
            }
            for i in 0..node.child_count() {
                if let Some(c) = node.child(i) {
                    if let Some(found) = find(c, kind, source) {
                        return Some(found);
                    }
                }
            }
            None
        }
        find(tree.root_node(), kind, source).unwrap_or_else(|| panic!("no {} found", kind))
    }

    #[test]
    fn field_and_deref_field_unify() {
        let (tree1, src1) = parse_expr("p->buf;");
        let n1 = first_expr_node(&tree1, &src1, "field_expression");
        let lv1 = lvalue_of(&n1, &src1).expect("lvalue");

        let (tree2, src2) = parse_expr("(*p).buf;");
        let n2 = first_expr_node(&tree2, &src2, "field_expression");
        let lv2 = lvalue_of(&n2, &src2).expect("lvalue");

        assert_eq!(lv1, lv2);
        assert_eq!(
            lv1,
            LValue::Field(Rc::new(LValue::Var("p".to_string())), "buf".to_string())
        );
    }

    #[test]
    fn subscript_is_index_insensitive() {
        let (tree1, src1) = parse_expr("arr[i]->x;");
        let n1 = first_expr_node(&tree1, &src1, "field_expression");
        let lv1 = lvalue_of(&n1, &src1).expect("lvalue");

        let (tree2, src2) = parse_expr("arr[j]->x;");
        let n2 = first_expr_node(&tree2, &src2, "field_expression");
        let lv2 = lvalue_of(&n2, &src2).expect("lvalue");

        assert_eq!(lv1, lv2);
    }

    #[test]
    fn root_var_on_nested_field_chain() {
        let (tree, src) = parse_expr("a->b->c;");
        let n = first_expr_node(&tree, &src, "field_expression");
        let lv = lvalue_of(&n, &src).expect("lvalue");
        assert_eq!(lv.root_var(), "a");
        assert!(lv.is_field());
    }

    #[test]
    fn resolve_canonical_breaks_cycles() {
        let mut map: AliasMap = HashMap::new();
        let a = LValue::Var("a".to_string());
        let b = LValue::Var("b".to_string());
        map.insert(a.clone(), b.clone());
        map.insert(b.clone(), a.clone());
        // Must terminate rather than looping forever.
        let _ = resolve_canonical(&map, &a);
    }

    #[test]
    fn crossing_deref_distinguishes_star_from_amp() {
        let (tree1, src1) = parse_expr("*p;");
        let n1 = first_expr_node(&tree1, &src1, "pointer_expression");
        let (lv1, crossed1) = lvalue_of_crossing_deref(&n1, &src1).expect("lvalue");
        assert_eq!(lv1, LValue::Var("p".to_string()));
        assert!(crossed1);

        let (tree2, src2) = parse_expr("&p;");
        let n2 = first_expr_node(&tree2, &src2, "pointer_expression");
        let (lv2, crossed2) = lvalue_of_crossing_deref(&n2, &src2).expect("lvalue");
        assert_eq!(lv2, LValue::Var("p".to_string()));
        assert!(!crossed2);
    }

    #[test]
    fn non_lvalue_expressions_return_none() {
        let (tree, src) = parse_expr("foo();");
        let n = first_expr_node(&tree, &src, "call_expression");
        assert_eq!(lvalue_of(&n, &src), None);
    }
}
