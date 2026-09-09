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
//! 4. A definition whose body unconditionally terminates the process, even
//!    with nothing declaring it noreturn -- pure-ftpd's `pure-pw.c` defines
//!    its own `static void no_mem(void) { fprintf(...); exit(...); }` with
//!    no attribute anywhere. Inferred to a fixpoint, so a wrapper around a
//!    wrapper is recognized too.
//! 5. seL4-style bare-identifier attribute macros (`void NORETURN foo(...)`)
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

/// Noreturn functions that do **not** end the process: control resumes
/// elsewhere in the same program, so anything still allocated when they are
/// called really is leaked. Callers reasoning about *process termination*
/// (rather than merely "does not return to my caller") must exclude these --
/// see [`is_process_terminating_name`].
const NON_TERMINATING_NORETURN_FUNCTIONS: &[&str] = &["longjmp", "siglongjmp"];

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

/// True if an `__attribute__((noreturn))` sits on the *declarator* rather
/// than on the declaration itself -- the trailing spelling,
/// `void no_mem(void) __attribute__((noreturn));`.
///
/// tree-sitter-c hangs a trailing attribute off an `attributed_declarator`
/// inside the declaration's `declarator`, not off the declaration node, so
/// [`has_noreturn_qualifier_or_attribute`]'s direct-children scan sees only
/// the leading spellings. pure-ftpd declares its `no_mem()` helper this way
/// in `ftpd.h`, which is the form task 1076 was filed against.
///
/// Attributes inside the parameter list are excluded: an attribute on a
/// parameter says nothing about whether the function returns.
fn has_declarator_noreturn_attribute(decl: &Node, func_declarator: &Node, source: &str) -> bool {
    let params = func_declarator.child_by_field_name("parameters");
    query::find_descendants_of_kinds(*decl, &["attribute_specifier"])
        .into_iter()
        .filter(|a| match params {
            Some(p) => a.start_byte() < p.start_byte() || a.start_byte() >= p.end_byte(),
            None => true,
        })
        .any(|a| get_node_text(&a, source).contains("noreturn"))
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
        if marked
            || has_noreturn_qualifier_or_attribute(&node, source)
            || has_declarator_noreturn_attribute(&node, &func_declarator, source)
        {
            names.insert(name);
        }
    }

    infer_terminating_definitions(root, source, &mut names);
    names
}

/// Maximum fixpoint rounds for [`infer_terminating_definitions`]. A wrapper
/// chain deeper than this is vanishingly rare, and a cap keeps a pathological
/// file from paying for repeated whole-tree walks.
const INFERENCE_MAX_ROUNDS: usize = 4;

/// Add every function *defined* in `root` whose body unconditionally ends the
/// process, iterating until nothing new is found so a wrapper calling a
/// wrapper is caught too.
///
/// Only process-*terminating* callees seed this. A local wrapper around
/// `longjmp` is genuinely noreturn, but adding it to this set would also make
/// [`is_process_terminating_name`] answer true for it -- that function
/// subtracts a fixed list of spellings, which cannot know about a
/// project-local name. Inferring it would silently convert every allocation
/// live across that wrapper from a real leak into a suppressed one, so the
/// wrapper is deliberately left unrecognized: a miss, not a wrong answer.
fn infer_terminating_definitions(root: &Node, source: &str, names: &mut HashSet<String>) {
    for _ in 0..INFERENCE_MAX_ROUNDS {
        let mut added = false;
        for def in query::find_descendants_of_kind(*root, "function_definition") {
            let Some(name) = definition_name(&def, source) else {
                continue;
            };
            if names.contains(&name) {
                continue;
            }
            if body_unconditionally_terminates(&def, source, names) {
                names.insert(name);
                added = true;
            }
        }
        if !added {
            break;
        }
    }
}

/// The declared name of a `function_definition`, or `None` when its
/// declarator does not resolve to one.
fn definition_name(def: &Node, source: &str) -> Option<String> {
    let declarator = def.child_by_field_name("declarator")?;
    let func_declarator = find_function_declarator(&declarator)?;
    let name_node = func_declarator.child_by_field_name("declarator")?;
    let name = get_node_text(&name_node, source).trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Whether every call of `def` ends the process.
///
/// Deliberately narrow: the body must contain no `return` and no `goto`
/// anywhere, and one of its *top-level* statements must be a call to a
/// process-terminating function. With no `return` and no `goto`, a top-level
/// statement is reached on every path that does not already diverge earlier,
/// so reaching it is enough -- and both weaker shapes this refuses to reason
/// about (an early `return` above the call, a `goto` jumping over it) are ones
/// where the function really can come back.
fn body_unconditionally_terminates(def: &Node, source: &str, names: &HashSet<String>) -> bool {
    let Some(body) = def.child_by_field_name("body") else {
        return false;
    };
    if !query::find_descendants_of_kinds(body, &["return_statement", "goto_statement"]).is_empty() {
        return false;
    }
    let mut cursor = body.walk();
    let terminates = body.children(&mut cursor).any(|stmt| {
        terminating_call_name(&stmt, source)
            .is_some_and(|callee| is_process_terminating_name(&callee, names))
    });
    terminates
}

/// The callee name of `stmt` when it is an `expression_statement` wrapping a
/// direct call, else `None`.
fn terminating_call_name(stmt: &Node, source: &str) -> Option<String> {
    if stmt.kind() != "expression_statement" {
        return None;
    }
    let call = stmt.child(0).filter(|c| c.kind() == "call_expression")?;
    let function = call.child_by_field_name("function")?;
    if function.kind() != "identifier" {
        return None;
    }
    Some(get_node_text(&function, source).trim().to_string())
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

/// True if calling `name` ends the process, so memory still held at that
/// point is reclaimed by the OS rather than leaked.
///
/// This is deliberately *narrower* than membership in `noreturn_names`.
/// "Noreturn" only promises control never comes back to the caller, which
/// `longjmp` satisfies while the program keeps running -- an allocation live
/// across it is a genuine leak. Treating the two as the same thing would
/// silently drop real MEM31-C findings, so the non-terminating spellings are
/// subtracted explicitly.
pub fn is_process_terminating_name(name: &str, noreturn_names: &HashSet<String>) -> bool {
    let name = name.trim();
    noreturn_names.contains(name) && !NON_TERMINATING_NORETURN_FUNCTIONS.contains(&name)
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
    fn infers_noreturn_from_a_definition_that_only_exits() {
        let (tree, source) =
            parse("static void no_mem(void) { fprintf(stderr, \"oom\"); exit(1); }\n");
        let names = collect_noreturn_function_names(&tree.root_node(), &source);
        assert!(names.contains("no_mem"));
    }

    #[test]
    fn infers_through_a_chain_of_wrappers() {
        let (tree, source) = parse(
            "static void die(void) { exit(1); }\n\
             static void bail(void) { die(); }\n",
        );
        let names = collect_noreturn_function_names(&tree.root_node(), &source);
        assert!(names.contains("die"));
        assert!(names.contains("bail"));
    }

    #[test]
    fn does_not_infer_when_an_earlier_return_can_escape() {
        let (tree, source) = parse("static void maybe(int x) { if (x) return; exit(1); }\n");
        let names = collect_noreturn_function_names(&tree.root_node(), &source);
        assert!(!names.contains("maybe"));
    }

    #[test]
    fn does_not_infer_when_the_exit_is_conditional() {
        let (tree, source) = parse("static void maybe(int x) { if (x) { exit(1); } }\n");
        let names = collect_noreturn_function_names(&tree.root_node(), &source);
        assert!(!names.contains("maybe"));
    }

    #[test]
    fn does_not_infer_a_longjmp_wrapper() {
        // Genuinely noreturn, but not process-terminating: inferring it would
        // make `is_process_terminating_name` answer true and turn every
        // allocation live across it into a suppressed leak.
        let (tree, source) = parse("static void unwind(void) { longjmp(env, 1); }\n");
        let names = collect_noreturn_function_names(&tree.root_node(), &source);
        assert!(!names.contains("unwind"));
        assert!(!is_process_terminating_name("unwind", &names));
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
    fn longjmp_is_noreturn_but_not_process_terminating() {
        let names: HashSet<String> = ["longjmp", "siglongjmp", "exit", "abort", "die_mem"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        // Ends the process: memory still held is reclaimed by the OS.
        assert!(is_process_terminating_name("exit", &names));
        assert!(is_process_terminating_name("abort", &names));
        assert!(is_process_terminating_name("die_mem", &names));

        // Noreturn, but the program keeps running -- a live allocation
        // across one of these really is leaked, so it must not suppress.
        assert!(!is_process_terminating_name("longjmp", &names));
        assert!(!is_process_terminating_name("siglongjmp", &names));

        // Not noreturn at all.
        assert!(!is_process_terminating_name("tls_extcert_exit", &names));
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
