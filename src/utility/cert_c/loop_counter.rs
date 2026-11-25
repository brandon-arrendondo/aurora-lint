//! A `for` loop's counter, proved to take only the values the loop steps it
//! through: what the loop's own header says of it is all that writes it.

use crate::analyze::name_writes::{self, NameScope, Scan};
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::node_children::NodeChildren;
use tree_sitter::Node;

/// What [`counting_loop`] proves of `for (v = low; v < limit; v += step)`.
pub(crate) struct CountingLoop<'t> {
    /// The block-scope declaration `v` names.
    pub decl: Node<'t>,
    /// The constant every iteration starts from.
    pub low: i64,
    /// The other operand of the condition's comparison.
    pub limit: Node<'t>,
    /// The comparison is `<=` (or `>=` with the operands reversed), so `v`
    /// reaches `limit` itself.
    pub inclusive: bool,
    /// The constant, above zero, the update adds.
    pub step: i64,
}

/// The counter `name` of `for_node` in `function`, when nothing but the
/// loop's header writes it: the initializer is `v = A` or `T v = A` with
/// `A` a constant `bound_int` reads, the condition compares `v` with one
/// operand and nothing else (`v < B`, `v <= B`, `B > v`, `B >= v`), the
/// update is `v++`, `++v` or `v += c` with `c > 0`, and `v` is a
/// non-`static` local whose address the function never takes. The body
/// neither writes `v` nor holds a label a `goto` could enter by, nor passes
/// `v` to a callee `scope` does not know as a function, nor uses a macro
/// whose replacement names `v`; and no macro anywhere in the function names
/// it. Inside the body `v` then lies in `[A, B)` (`[A, B]` when inclusive),
/// provided its type holds every value it takes, which is the caller's to
/// check, as is what `B` is.
pub(crate) fn counting_loop<'t>(
    for_node: &Node<'t>,
    name: &str,
    function: &Node<'t>,
    scope: &NameScope,
    source: &str,
    bound_int: &dyn Fn(&Node) -> Option<i64>,
) -> Option<CountingLoop<'t>> {
    let (decl, low) = counter_initializer(for_node, name, source, bound_int)?;
    if ast_utils::declaration_has_storage_class(&decl, "static", source) {
        return None;
    }
    let decl_id = decl.id();
    let names_counter = |n: &Node| {
        n.kind() == "identifier"
            && get_node_text(n, source) == name
            && local_declaration_id(n, name, source) == Some(decl_id)
    };

    let condition = name_writes::strip_parens(for_node.child_by_field_name("condition")?);
    if condition.kind() != "binary_expression" {
        return None;
    }
    let (left, right) = (
        condition.child_by_field_name("left")?,
        condition.child_by_field_name("right")?,
    );
    let op = condition.child_by_field_name("operator")?;
    let (limit, inclusive) = match get_node_text(&op, source) {
        "<" if names_counter(&left) => (right, false),
        "<=" if names_counter(&left) => (right, true),
        ">" if names_counter(&right) => (left, false),
        ">=" if names_counter(&right) => (left, true),
        _ => return None,
    };

    let update = name_writes::strip_parens(for_node.child_by_field_name("update")?);
    let operator = update
        .child_by_field_name("operator")
        .map(|o| get_node_text(&o, source));
    let step = match update.kind() {
        "update_expression"
            if operator == Some("++")
                && update
                    .child_by_field_name("argument")
                    .is_some_and(|a| names_counter(&a)) =>
        {
            1
        }
        "assignment_expression"
            if operator == Some("+=")
                && update
                    .child_by_field_name("left")
                    .is_some_and(|l| names_counter(&l)) =>
        {
            bound_int(&update.child_by_field_name("right")?).filter(|&c| c > 0)?
        }
        _ => return None,
    };

    let body = for_node.child_by_field_name("body")?;
    // The body is scanned for every write; the rest of the function for
    // what a name could expand to and for `&v`, through which the body
    // could write (`SAVE()` stashing `&i` before the loop, `*p = 300;`
    // inside it).
    let function_body = function.child_by_field_name("body")?;
    if scope.may_write(
        &body,
        source,
        name,
        &names_counter,
        Scan::Writes {
            entered_from_outside: true,
        },
    ) || scope.may_write(
        &function_body,
        source,
        name,
        &names_counter,
        Scan::Expansions,
    ) {
        return None;
    }
    Some(CountingLoop {
        decl,
        low,
        limit,
        inclusive,
        step,
    })
}

/// The declaration a `for` initializer binds `name` with, and the constant
/// it starts from: `T v = A` declares it there, `v = A` assigns the local
/// it resolves to.
fn counter_initializer<'t>(
    for_node: &Node<'t>,
    name: &str,
    source: &str,
    bound_int: &dyn Fn(&Node) -> Option<i64>,
) -> Option<(Node<'t>, i64)> {
    let init = for_node.child_by_field_name("initializer")?;
    match init.kind() {
        "declaration" => {
            let mut declarators = init
                .named_child_nodes()
                .filter(|c| c.kind() == "init_declarator");
            let only = declarators.next()?;
            if declarators.next().is_some() {
                return None;
            }
            let var = only.child_by_field_name("declarator")?;
            if var.kind() != "identifier" || get_node_text(&var, source) != name {
                return None;
            }
            let value = bound_int(&only.child_by_field_name("value")?)?;
            Some((init, value))
        }
        "assignment_expression" => {
            let op = init.child_by_field_name("operator")?;
            let left = init.child_by_field_name("left")?;
            if get_node_text(&op, source) != "="
                || left.kind() != "identifier"
                || get_node_text(&left, source) != name
            {
                return None;
            }
            let value = bound_int(&init.child_by_field_name("right")?)?;
            match ast_utils::resolve_identifier_binding(&left, name, source)? {
                ast_utils::IdentifierBinding::Local(decl) => Some((decl, value)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The id of the block-scope declaration an occurrence of `name` refers to.
pub(crate) fn local_declaration_id(ident: &Node, name: &str, source: &str) -> Option<usize> {
    match ast_utils::resolve_identifier_binding(ident, name, source)? {
        ast_utils::IdentifierBinding::Local(decl) => Some(decl.id()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lang_parsing_substrate::query;

    fn parse_c_code(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let language = crate::parser::c_language();
        parser.set_language(&language).unwrap();
        parser.parse(code, None).unwrap()
    }

    /// What `counting_loop` proves of `i` in the first `for` of `src`: the
    /// start, the limit's text and whether it is reached.
    fn proof(src: &str) -> Option<(i64, String, bool)> {
        let tree = parse_c_code(src);
        let root = tree.root_node();
        let function = query::find_descendants_of_kind(root, "function_definition")[0];
        let for_node = query::find_descendants_of_kind(root, "for_statement")[0];
        let scope = NameScope::of_file(&root, src, None);
        let bound_int = |n: &Node| get_node_text(n, src).parse::<i64>().ok();
        counting_loop(&for_node, "i", &function, &scope, src, &bound_int)
            .map(|c| (c.low, get_node_text(&c.limit, src).to_string(), c.inclusive))
    }

    #[test]
    fn proves_a_counter_only_its_header_writes() {
        assert_eq!(
            proof("int t(int); void f(int n) { int i; for (i = 0; i < n; i++) t(i); }"),
            Some((0, "n".to_string(), false))
        );
        assert_eq!(
            proof("void f(int n) { for (int i = 2; n >= i; i += 2) { } }"),
            Some((2, "n".to_string(), true))
        );
    }

    #[test]
    fn a_counter_written_or_entered_from_elsewhere_is_not_proved() {
        // Written in the body.
        assert_eq!(
            proof("void f(int n) { int i; for (i = 0; i < n; i++) i += 3; }"),
            None
        );
        // Static.
        assert_eq!(
            proof("void f(int n) { static int i; for (i = 0; i < n; i++) { } }"),
            None
        );
        // A label in the body a goto can enter by.
        assert_eq!(
            proof("void f(int n) { int i = 9; goto in; for (i = 0; i < n; i++) { in: ; } }"),
            None
        );
        // Its address taken elsewhere in the function.
        assert_eq!(
            proof("void g(int *); void f(int n) { int i; g(&i); for (i = 0; i < n; i++) { } }"),
            None
        );
        // A condition that tests more than the counter.
        assert_eq!(
            proof("int t(int); void f(int n) { int i; for (i = 0; t(i) && i < n; i++) { } }"),
            None
        );
    }
}
