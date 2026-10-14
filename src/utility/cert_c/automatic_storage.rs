//! Which automatic object an expression addresses, and what a local pointer
//! holds: the questions DCL30-C (TS 17961 addrescape) asks of a returned or
//! stored value.
//!
//! An object has automatic storage duration when a block-scope declaration
//! declares it without `static`, `extern` or a thread-storage specifier, when
//! it is a parameter, or when it is a compound literal inside a function body
//! (C11 6.2.4p6, 6.5.2.5p5). Everything here resolves a name to the
//! declaration that binds it (ADR-0006), never by spelling. An array
//! parameter is a pointer (6.7.6.3p7), so naming one yields no address of
//! automatic storage. A member reached through `->` or an element reached
//! through a pointer lies in whatever the pointer points at, which nothing
//! here claims to know. A `_Thread_local` object has thread storage, not
//! automatic: the parser respells the keyword as `thread_local`, which the
//! grammar reads as a storage class.
//!
//! Known misses, none reported: an array member of a local structure named
//! as a value (`return s.a;`, which decays to an address in `s`), storage
//! from `alloca`, and `&x` handed to a callee that stores it.

use crate::utility::cert_c::ast_utils::{
    declaration_has_storage_class, declaration_is_thread_local, get_node_text,
    resolve_identifier_binding, resolve_identifier_declarator, IdentifierBinding,
};
use crate::utility::cert_c::guard_dominance::{dominating_assignment, WriteIndex};
use tree_sitter::Node;

/// How an automatic object came to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutomaticKind {
    /// Declared in a block without `static`, `extern` or a thread-storage
    /// specifier.
    Local,
    /// A parameter object.
    Parameter,
    /// A compound literal in a function body: an object of its block, new
    /// on every execution of the block (C11 6.5.2.5p5, p16).
    CompoundLiteral,
}

/// An object with automatic storage duration.
#[derive(Debug, Clone)]
pub struct AutomaticObject<'a> {
    /// The declared name, or the literal's text for a compound literal.
    pub name: String,
    /// The declarator that declares it, or the compound literal itself.
    pub node: Node<'a>,
    /// Whether a declaration, a parameter or a compound literal.
    pub kind: AutomaticKind,
}

/// How far a local pointer's value is followed through copies from other
/// local pointers (`q = buf; p = q;`) before giving up.
const MAX_COPY_HOPS: usize = 4;

/// The automatic object whose own storage `lvalue` lies in: an automatic
/// variable or parameter, a `.` member of one, an element of an automatic
/// array (as many subscripts as the array has dimensions), or a compound
/// literal in a function body. `None` for static, thread or allocated
/// storage, and for anything reached through a pointer (`p->m`, `*p`,
/// `p[i]`, or `s.m[i]`, whose member may be a pointer).
pub fn automatic_object<'a>(lvalue: &Node<'a>, source: &str) -> Option<AutomaticObject<'a>> {
    let lvalue = strip_parens(*lvalue);
    match lvalue.kind() {
        "identifier" => automatic_variable(&lvalue, source),
        "field_expression" => {
            let through_pointer = lvalue
                .child_by_field_name("operator")
                .is_some_and(|op| get_node_text(&op, source) == "->");
            if through_pointer {
                return None;
            }
            automatic_object(&lvalue.child_by_field_name("argument")?, source)
        }
        "subscript_expression" => {
            let (root, depth) = subscript_root(lvalue);
            let root = strip_parens(root);
            if root.kind() != "identifier" {
                return None;
            }
            let object = automatic_variable(&root, source)?;
            (object.kind == AutomaticKind::Local && array_rank(&object.node) >= depth)
                .then_some(object)
        }
        "compound_literal_expression" => compound_literal(&lvalue, source),
        _ => None,
    }
}

/// The automatic object `expr`'s value is the address of, read from the
/// expression alone, through parentheses and casts:
/// - an automatic array named as a value (it decays to a pointer to its
///   first element);
/// - `&lvalue` for an `automatic_object`;
/// - `array + n`, `n + array` or `array - n` on such an address;
/// - a compound literal of array type, as a value;
/// - either arm of a conditional, and the last operand of a comma.
///
/// A pointer variable's own value is [`pointer_value_origin`]'s question.
pub fn automatic_address<'a>(expr: &Node<'a>, source: &str) -> Option<AutomaticObject<'a>> {
    let expr = strip_parens_and_casts(*expr);
    match expr.kind() {
        "identifier" => automatic_variable(&expr, source)
            .filter(|o| o.kind == AutomaticKind::Local && array_rank(&o.node) > 0),
        "pointer_expression" => {
            let address_of = expr
                .child_by_field_name("operator")
                .is_some_and(|op| get_node_text(&op, source) == "&");
            if !address_of {
                return None;
            }
            automatic_object(&expr.child_by_field_name("argument")?, source)
        }
        "binary_expression" => {
            let op = expr.child_by_field_name("operator")?;
            let left = expr.child_by_field_name("left")?;
            let right = expr.child_by_field_name("right")?;
            let (l, r) = (
                automatic_address(&left, source),
                automatic_address(&right, source),
            );
            match get_node_text(&op, source) {
                // Two addresses added are not C; an address and an integer
                // stay in the object.
                "+" => match (l, r) {
                    (Some(o), None) | (None, Some(o)) => Some(o),
                    _ => None,
                },
                // An address minus an address is an integer.
                "-" => l.filter(|_| r.is_none()),
                _ => None,
            }
        }
        "conditional_expression" => {
            let arm = |field| {
                expr.child_by_field_name(field)
                    .and_then(|a| automatic_address(&a, source))
            };
            arm("consequence").or_else(|| arm("alternative"))
        }
        "comma_expression" => automatic_address(&expr.child_by_field_name("right")?, source),
        "compound_literal_expression" => {
            let is_array = expr
                .child_by_field_name("type")
                .is_some_and(|t| has_kind(&t, "abstract_array_declarator"));
            if is_array {
                compound_literal(&expr, source)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The automatic object whose address the pointer variable `ident` holds
/// when `site` executes: the value of its dominating assignment or
/// initializer ([`dominating_assignment`]), followed through copies from
/// other variables for up to [`MAX_COPY_HOPS`] hops. `None` whenever that
/// value is not known (a write in a branch, the address taken, a label,
/// no write before the function's top) or is not an automatic address, so
/// an unknown value is never reported. `index` indexes the function body
/// holding `site`.
pub fn pointer_value_origin<'a>(
    ident: &Node<'a>,
    site: &Node<'a>,
    source: &str,
    index: &WriteIndex,
) -> Option<AutomaticObject<'a>> {
    let mut ident = strip_parens_and_casts(*ident);
    let mut site = *site;
    for _ in 0..MAX_COPY_HOPS {
        if ident.kind() != "identifier" {
            return None;
        }
        let name = get_node_text(&ident, source);
        // Only a variable of this frame has a value the body decides; a
        // file-scope or static one may have been written by anyone.
        let binding = resolve_identifier_binding(&ident, name, source)?;
        match binding {
            IdentifierBinding::Parameter(_) => {}
            IdentifierBinding::Local(decl) => {
                if declaration_has_storage_class(&decl, "static", source)
                    || declaration_has_storage_class(&decl, "extern", source)
                {
                    return None;
                }
            }
            IdentifierBinding::Global(_) => return None,
        }
        let write = dominating_assignment(name, &site, source, index)?;
        if let Some(object) = automatic_address(&write.value, source) {
            return Some(object);
        }
        ident = strip_parens_and_casts(write.value);
        site = write.statement;
    }
    None
}

/// Whether `ident` names an array object here, so that indexing it stays
/// inside the array's own storage: an array declarator that is not a
/// parameter's (an array parameter is a pointer). Any storage duration.
pub fn names_array_object(ident: &Node, source: &str) -> bool {
    let name = get_node_text(ident, source);
    let Some((_, declarator)) = resolve_identifier_declarator(ident, name, source) else {
        return false;
    };
    array_rank(&declarator) > 0
        && !matches!(
            resolve_identifier_binding(ident, name, source),
            Some(IdentifierBinding::Parameter(_))
        )
}

/// The automatic variable or parameter `ident` names, by the declaration
/// that binds it here.
fn automatic_variable<'a>(ident: &Node<'a>, source: &str) -> Option<AutomaticObject<'a>> {
    let name = get_node_text(ident, source);
    let binding = resolve_identifier_binding(ident, name, source)?;
    let (decl, declarator) = resolve_identifier_declarator(ident, name, source)?;
    if has_kind(&declarator, "function_declarator") {
        return None;
    }
    let kind = match binding {
        IdentifierBinding::Parameter(_) => AutomaticKind::Parameter,
        IdentifierBinding::Local(_)
            if !declaration_has_storage_class(&decl, "static", source)
                && !declaration_has_storage_class(&decl, "extern", source)
                && !declaration_is_thread_local(&decl, source) =>
        {
            AutomaticKind::Local
        }
        _ => return None,
    };
    Some(AutomaticObject {
        name: name.to_string(),
        node: declarator,
        kind,
    })
}

/// A compound literal inside a function body. At file scope one has
/// static storage duration.
fn compound_literal<'a>(literal: &Node<'a>, source: &str) -> Option<AutomaticObject<'a>> {
    let mut parent = literal.parent();
    while let Some(p) = parent {
        if p.kind() == "function_definition" {
            return Some(AutomaticObject {
                name: get_node_text(literal, source).to_string(),
                node: *literal,
                kind: AutomaticKind::CompoundLiteral,
            });
        }
        parent = p.parent();
    }
    None
}

/// The expression a chain of subscripts indexes, and how many subscripts
/// the chain has: `a[i][j]` is `(a, 2)`.
fn subscript_root(mut node: Node) -> (Node, usize) {
    let mut depth = 0;
    while node.kind() == "subscript_expression" {
        depth += 1;
        match node.child_by_field_name("argument") {
            Some(arg) => node = strip_parens(arg),
            None => break,
        }
    }
    (node, depth)
}

/// How many array dimensions `declarator` gives the name it declares before
/// any pointer: `a[2][3]` has 2, `*a[3]` (an array of pointers) has 1,
/// `(*a)[3]` (a pointer to an array) and `p` have 0. A declarator applies
/// from the name outward, so the chain is read from the name up.
fn array_rank(declarator: &Node) -> usize {
    let mut chain = Vec::new();
    let mut node = Some(*declarator);
    while let Some(n) = node {
        chain.push(n.kind());
        node = match n.kind() {
            "init_declarator" | "array_declarator" | "pointer_declarator" => {
                n.child_by_field_name("declarator")
            }
            "parenthesized_declarator" => n.named_child(0),
            _ => None,
        };
    }
    chain
        .iter()
        .rev()
        .filter(|k| **k != "parenthesized_declarator" && **k != "identifier")
        .take_while(|k| **k == "array_declarator")
        .count()
}

/// Whether `node` is, or has as a descendant, a node of `kind`.
fn has_kind(node: &Node, kind: &str) -> bool {
    if node.kind() == kind {
        return true;
    }
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).any(|c| has_kind(&c, kind));
    found
}

fn strip_parens(node: Node) -> Node {
    if node.kind() == "parenthesized_expression" {
        let mut cursor = node.walk();
        let inner = node
            .named_children(&mut cursor)
            .find(|c| c.kind() != "comment");
        if let Some(inner) = inner {
            return strip_parens(inner);
        }
    }
    node
}

fn strip_parens_and_casts(node: Node) -> Node {
    match node.kind() {
        "cast_expression" => node
            .child_by_field_name("value")
            .map_or(node, strip_parens_and_casts),
        "parenthesized_expression" => {
            let inner = strip_parens(node);
            if inner.id() == node.id() {
                node
            } else {
                strip_parens_and_casts(inner)
            }
        }
        _ => node,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lang_parsing_substrate::query;

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        parser.parse(source, None).unwrap()
    }

    /// `automatic_address` of each `return` operand, in order.
    fn returned(source: &str) -> Vec<Option<(String, AutomaticKind)>> {
        let tree = parse(source);
        query::find_descendants_of_kind(tree.root_node(), "return_statement")
            .iter()
            .map(|r| {
                let e = r.named_child(0).unwrap();
                automatic_address(&e, source).map(|o| (o.name, o.kind))
            })
            .collect()
    }

    fn local(name: &str) -> Option<(String, AutomaticKind)> {
        Some((name.to_string(), AutomaticKind::Local))
    }

    #[test]
    fn arrays_decay_and_address_of_names_the_object() {
        let src = "struct s { int m; int a[2]; };\n\
                   int *f(struct s p) {\n\
                     char buf[8]; int x; struct s v; int m[2][3]; int *pa[3];\n\
                     return buf; return &x; return &v.m; return &m[1][2];\n\
                     return (int *)buf + 2; return &p; return &p.m;\n\
                     return &pa[1]; return &pa[1][0]; return m[1];\n\
                   }";
        assert_eq!(
            returned(src),
            vec![
                local("buf"),
                local("x"),
                local("v"),
                local("m"),
                local("buf"),
                Some(("p".into(), AutomaticKind::Parameter)),
                Some(("p".into(), AutomaticKind::Parameter)),
                local("pa"),
                None, // pa[1] is a pointer; [0] indexes its pointee
                None, // m[1] is a row; decaying rows is not followed
            ]
        );
    }

    #[test]
    fn static_global_thread_heap_and_pointee_are_not_automatic() {
        let src = "int g[4]; struct s { int m; };\n\
                   int *f(char a[], int *p, struct s *ps) {\n\
                     static int st[2]; extern int ex[2]; __thread int t[2];\n\
                     return g; return st; return ex; return t; return a;\n\
                     return &p[1]; return &ps->m; return &*p; return p;\n\
                     return buf_end - buf;\n\
                   }";
        assert_eq!(returned(src), vec![None; 10]);
    }

    #[test]
    fn a_parameter_array_is_a_pointer_but_its_address_is_automatic() {
        let src = "char **f(char a[]) { return a; return &a; }";
        assert_eq!(
            returned(src),
            vec![None, Some(("a".into(), AutomaticKind::Parameter))]
        );
    }

    #[test]
    fn shadowing_resolves_to_the_nearest_declaration() {
        let src = "char buf[4];\n\
                   char *f(void) { return buf; { char buf[4]; return buf; } }";
        assert_eq!(returned(src), vec![None, local("buf")]);
    }

    #[test]
    fn compound_literals_in_a_body_are_automatic_and_at_file_scope_static() {
        let src = "int *p = (int[]){1};\n\
                   int *f(int c) {\n\
                     return (int[]){1, 2}; return &(struct q){0}.x; return &(int){3};\n\
                     return c ? (int *)0 : (int[]){4}; return (struct q){0}.y;\n\
                   }";
        let got: Vec<_> = returned(src)
            .into_iter()
            .map(|o| o.map(|(_, k)| k))
            .collect();
        assert_eq!(
            got,
            vec![
                Some(AutomaticKind::CompoundLiteral),
                Some(AutomaticKind::CompoundLiteral),
                Some(AutomaticKind::CompoundLiteral),
                Some(AutomaticKind::CompoundLiteral),
                None,
            ]
        );
        let tree = parse(src);
        let lit =
            query::find_descendants_of_kind(tree.root_node(), "compound_literal_expression")[0];
        assert!(automatic_object(&lit, src).is_none());
    }

    /// `pointer_value_origin` of each returned identifier.
    fn origins(source: &str) -> Vec<Option<String>> {
        let tree = parse(source);
        let mut out = Vec::new();
        for func in query::find_descendants_of_kind(tree.root_node(), "function_definition") {
            let body = func.child_by_field_name("body").unwrap();
            let index = WriteIndex::new(&body, source);
            for r in query::find_descendants_of_kind(body, "return_statement") {
                let e = r.named_child(0).unwrap();
                out.push(pointer_value_origin(&e, &r, source, &index).map(|o| o.name));
            }
        }
        out
    }

    #[test]
    fn a_pointer_holds_what_its_dominating_write_stored() {
        let src = "#include <stdlib.h>\n\
                   char *a(void) { char buf[4]; char *p; p = &buf[1]; return p; }\n\
                   char *b(void) { char buf[4]; char *q = buf; char *p = q; return p; }\n\
                   char *c(void) { char *p = malloc(4); return p; }\n\
                   char *d(int k) { char buf[4]; char *p = 0; if (k) p = buf; return p; }\n\
                   char *e(void) { static char s[4]; char *p = s; return p; }\n\
                   char *f(char *in) { char buf[4]; in = buf; return in; }\n\
                   char *g(void) { char buf[4]; static char *p; p = buf; return p; }\n\
                   char *h(char *in) { return in; }";
        assert_eq!(
            origins(src),
            vec![
                Some("buf".into()),
                Some("buf".into()),
                None,
                None, // written in a branch: not known
                None,
                Some("buf".into()),
                None, // a static pointer may be written by anyone
                None,
            ]
        );
    }
}
