//! Shared noreturn-function detection (task 648).
//!
//! EXP34-C (and every other CFG-consuming rule -- EXP33-C, MEM01-C, ARR30-C,
//! INT30/31/32/33/34-C) models a function's control flow via
//! [`crate::analyze::cfg`], which only treats `return`/`break`/`continue`/
//! `goto` as terminating a basic block. A call to a function that never
//! returns (`abort()`, a `_Noreturn`-qualified error handler, ...) has
//! exactly the same effect on reachability but wasn't recognized, so a null
//! check whose failure branch calls one of these was invisible to the CFG
//! and the guarded dereference after it looked unguarded. Found on seL4's
//! `src/fastpath/fastpath.c` (task 598's delta-adjudication): `cap_pd`/
//! `reply` are only reached after a NULL check whose failure branch calls
//! `slowpath()`, declared `NORETURN` in `include/arch/*/arch/fastpath/
//! fastpath.h`.
//!
//! This module collects the set of function names known to be noreturn for
//! a translation unit, combining four signals:
//! 1. The fixed C standard library list (`abort`, `exit`, ...).
//! 2. `_Noreturn`-qualified declarations/definitions (a real C11 keyword,
//!    parses cleanly).
//! 3. `__attribute__((noreturn))` / `__attribute__((__noreturn__))` (a real
//!    GNU extension, also parses cleanly).
//! 4. seL4-style bare-identifier attribute macros (`void NORETURN foo(...)`)
//!    whose `#define` lives in a header this single-file parse never sees.
//!    tree-sitter-c's grammar has no production for an unresolvable
//!    identifier between a return type and a declarator, so
//!    `unknown_identifier_recovery`'s ERROR-node recovery blanks the token
//!    -- except for names in [`NORETURN_ATTRIBUTE_MACRO_NAMES`], where it
//!    leaves [`MARKER`] in its place instead (same length-preserving
//!    recoverable-marker idiom task 663 used for label-guarded
//!    preprocessor directives), so this module can still recognize the
//!    declaration as noreturn post-parse.

use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

/// C standard library functions that never return to their caller.
const STDLIB_NORETURN_FUNCTIONS: &[&str] = &["abort", "exit", "_Exit", "quick_exit", "longjmp"];

/// Bare-identifier attribute-macro spellings recognized as marking a
/// function noreturn when their `#define` isn't visible to this parse.
/// Kept short and explicit -- unlike `_Noreturn`/`__attribute__((noreturn))`
/// this is a name-based heuristic, so it only covers spellings actually
/// seen in a pinned real-world corpus (seL4's `NORETURN`, from
/// `include/util.h`: `#define NORETURN __attribute__((__noreturn__))`).
pub const NORETURN_ATTRIBUTE_MACRO_NAMES: &[&str] = &["NORETURN"];

/// Marker written in place of a blanked [`NORETURN_ATTRIBUTE_MACRO_NAMES`]
/// token. Short enough to fit inside the shortest name currently in that
/// list, padded with spaces to preserve the original byte length.
const MARKER: &str = "/*R*/";

/// Write [`MARKER`] into `source[start..end]`, right-padded with spaces to
/// preserve length. Returns `None` (caller should fall back to a plain
/// blank) if the marker doesn't fit -- defensive against a future,
/// shorter-than-`MARKER` addition to [`NORETURN_ATTRIBUTE_MACRO_NAMES`].
pub fn write_marker(source: &str, start: usize, end: usize) -> Option<String> {
    let len = end - start;
    if len < MARKER.len() {
        return None;
    }
    let mut out = String::with_capacity(source.len());
    out.push_str(&source[..start]);
    out.push_str(MARKER);
    out.push_str(&" ".repeat(len - MARKER.len()));
    out.push_str(&source[end..]);
    Some(out)
}

/// True if `text` (already the trimmed span between a declaration's return
/// type and its declarator) contains the recovered [`MARKER`].
fn has_marker(text: &str) -> bool {
    text.contains(MARKER)
}

/// Depth-first search for a `function_declarator`, descending through
/// `pointer_declarator` wrappers -- mirrors
/// `utility::cert_c::ast_utils::find_function_declarator`, reimplemented
/// here since that one is private to its module.
fn find_function_declarator<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "function_declarator" {
        return Some(*node);
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(found) = find_function_declarator(&child) {
                return Some(found);
            }
        }
    }
    None
}

/// True if `decl_or_def` (a `declaration` or `function_definition` node)
/// carries a `_Noreturn` qualifier or a
/// `__attribute__((noreturn))`/`__attribute__((__noreturn__))` attribute
/// among its direct children.
fn has_noreturn_qualifier_or_attribute(decl_or_def: &Node, source: &str) -> bool {
    let mut cursor = decl_or_def.walk();
    let result = decl_or_def.children(&mut cursor).any(|c| match c.kind() {
        "type_qualifier" => get_node_text(&c, source).trim() == "_Noreturn",
        "attribute_specifier" => {
            let text = get_node_text(&c, source);
            text.contains("noreturn")
        }
        _ => false,
    });
    result
}

/// Collect the names of every function in `root` recognized as noreturn by
/// any of the four signals documented at module level.
pub fn collect_noreturn_function_names(root: &Node, source: &str) -> HashSet<String> {
    let mut names: HashSet<String> = STDLIB_NORETURN_FUNCTIONS
        .iter()
        .map(|s| s.to_string())
        .collect();

    for node in query::find_descendants_of_kinds(*root, &["declaration", "function_definition"]) {
        let declarator = match node.child_by_field_name("declarator") {
            Some(d) => d,
            None => continue,
        };
        let Some(func_declarator) = find_function_declarator(&declarator) else {
            continue;
        };
        let Some(name_node) = func_declarator.child_by_field_name("declarator") else {
            continue;
        };
        let name = get_node_text(&name_node, source).trim().to_string();
        if name.is_empty() {
            continue;
        }

        let marked = has_marker(&source[node.start_byte()..func_declarator.start_byte()]);
        if marked || has_noreturn_qualifier_or_attribute(&node, source) {
            names.insert(name);
        }
    }

    names
}

/// True if `node` is an `expression_statement` wrapping a direct call to a
/// function in `noreturn_names`.
pub fn is_noreturn_call_statement(
    node: &Node,
    source: &str,
    noreturn_names: &HashSet<String>,
) -> bool {
    if node.kind() != "expression_statement" {
        return false;
    }
    let Some(call) = node.child(0).filter(|c| c.kind() == "call_expression") else {
        return false;
    };
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "identifier" {
        return false;
    }
    let name = get_node_text(&function, source).trim();
    noreturn_names.contains(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::CParser;

    fn parse(src: &str) -> (tree_sitter::Tree, String) {
        let mut parser = CParser::new().expect("parser");
        parser.parse_source(src).expect("parse")
    }

    #[test]
    fn stdlib_names_always_present() {
        let (tree, source) = parse("int main(void) { return 0; }\n");
        let names = collect_noreturn_function_names(&tree.root_node(), &source);
        assert!(names.contains("abort"));
        assert!(names.contains("exit"));
        assert!(names.contains("longjmp"));
    }

    #[test]
    fn recognizes_c11_noreturn_keyword() {
        let (tree, source) = parse("_Noreturn void die(void) { for (;;) {} }\n");
        let names = collect_noreturn_function_names(&tree.root_node(), &source);
        assert!(names.contains("die"));
    }

    #[test]
    fn recognizes_gnu_attribute() {
        let (tree, source) = parse("__attribute__((noreturn)) void die(void) { for (;;) {} }\n");
        let names = collect_noreturn_function_names(&tree.root_node(), &source);
        assert!(names.contains("die"));
    }

    #[test]
    fn recognizes_marker_recovered_bare_macro_prototype() {
        // No local #define for NORETURN -- exactly the seL4 shape: the
        // prototype is what unknown_identifier_recovery blanks/marks; the
        // definition can be a plain, ordinary function.
        let src = "void NORETURN slowpath(int x);\nvoid slowpath(int x) { for (;;) {} }\n";
        let (tree, source) = parse(src);
        assert!(source.contains(MARKER), "expected marker in: {source:?}");
        let names = collect_noreturn_function_names(&tree.root_node(), &source);
        assert!(names.contains("slowpath"));
    }

    #[test]
    fn does_not_flag_unrelated_unknown_macro() {
        // VISIBLE has no local #define either, but it isn't in
        // NORETURN_ATTRIBUTE_MACRO_NAMES, so it stays a plain blank and
        // must not make `foo` noreturn.
        let src = "void VISIBLE foo(void) { return; }\n";
        let (tree, source) = parse(src);
        let names = collect_noreturn_function_names(&tree.root_node(), &source);
        assert!(!names.contains("foo"));
    }

    #[test]
    fn is_noreturn_call_statement_matches_expression_statement_call() {
        let src = "void f(void) { abort(); }\n";
        let (tree, source) = parse(src);
        let names = collect_noreturn_function_names(&tree.root_node(), &source);
        let call_stmt =
            query::find_descendants_of_kinds(tree.root_node(), &["expression_statement"])
                .into_iter()
                .next()
                .expect("expression_statement");
        assert!(is_noreturn_call_statement(&call_stmt, &source, &names));
    }
}
