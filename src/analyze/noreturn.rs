//! Shared noreturn-function detection.
//!
//! EXP34-C (and every other CFG-consuming rule -- EXP33-C, MEM01-C, ARR30-C,
//! INT30/31/32/33/34-C) models a function's control flow via
//! [`crate::analyze::cfg`], which only treats `return`/`break`/`continue`/
//! `goto` as terminating a basic block. A call to a function that never
//! returns (`abort()`, a `_Noreturn`-qualified error handler, ...) has
//! exactly the same effect on reachability but wasn't recognized, so a null
//! check whose failure branch calls one of these was invisible to the CFG
//! and the guarded dereference after it looked unguarded. Found on seL4's
//! `src/fastpath/fastpath.c` (an earlier fix's delta-adjudication): `cap_pd`/
//! `reply` are only reached after a NULL check whose failure branch calls
//! `slowpath()`, declared `NORETURN` in `include/arch/*/arch/fastpath/
//! fastpath.h`.
//!
//! This module collects the set of function names known to be noreturn for
//! a translation unit, from three signals:
//! 1. The fixed C standard library list (`abort`, `exit`, ...), trusted only
//!    when the declared environment honors that library contract
//!    (`stdlib_noreturn`: hosted, or a declared libc model).
//! 2. `_Noreturn`-qualified declarations/definitions (C11 6.7.4p8), trusted
//!    only when `trust_noreturn_keyword` holds (the default policy).
//! 3. A definition whose body unconditionally terminates the process, even
//!    with nothing declaring it noreturn -- pure-ftpd's `pure-pw.c` defines
//!    its own `static void no_mem(void) { fprintf(...); exit(...); }` with
//!    no attribute anywhere. Inferred to a fixpoint, so a wrapper around a
//!    wrapper is recognized too. This is the only proof the strict policy
//!    accepts for a project function.
//!
//! `__attribute__((noreturn))` is proof under neither policy (ADR-0015): it
//! is a promise the compiler does not check, so a function declared with it
//! is noreturn here only when its body is verified to be. The same holds for
//! a bare-identifier attribute macro such as seL4's `NORETURN`, whose
//! expansion is that attribute: it is not recognized by its spelling at all.
//!
//! Signals 1 and 2 change what signal 3 infers (a wrapper around `exit` or a
//! `_Noreturn` function is noreturn only when that callee is), so the names
//! are collected once per combination of `stdlib_noreturn` and
//! `trust_noreturn_keyword`, as a [`ByNoreturnTrust`]. A prescan records all
//! four and a rule picks one with
//! [`ByNoreturnTrust::get`], which keeps a saved prescan valid under every
//! setting.

use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

/// A value computed under each combination of the two options that decide
/// what counts as noreturn: `trust_noreturn_keyword` (policy: is a `_Noreturn`
/// declaration proof?) and `stdlib_noreturn` (environment: do `abort`, `exit`
/// and the rest honor their library contract?).
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ByNoreturnTrust<T> {
    /// Keyword and library contract both trusted (the default preset).
    pub keyword_and_stdlib: T,
    /// Only the library contract trusted (strict policy on a declared libc).
    pub stdlib_only: T,
    /// Only the keyword trusted (default policy, freestanding, no libc).
    pub keyword_only: T,
    /// Neither: only a body verified never to return (the strict preset),
    /// which with no library contract leaves nothing to verify against.
    pub neither: T,
}

impl<T> ByNoreturnTrust<T> {
    /// The value for `settings`.
    pub fn get(&self, settings: &AnalysisSettings) -> &T {
        match (
            settings.flag("trust_noreturn_keyword"),
            settings.flag("stdlib_noreturn"),
        ) {
            (true, true) => &self.keyword_and_stdlib,
            (false, true) => &self.stdlib_only,
            (true, false) => &self.keyword_only,
            (false, false) => &self.neither,
        }
    }

    /// Apply `f` under each combination.
    pub fn map<U>(&self, f: impl Fn(&T) -> U) -> ByNoreturnTrust<U> {
        ByNoreturnTrust {
            keyword_and_stdlib: f(&self.keyword_and_stdlib),
            stdlib_only: f(&self.stdlib_only),
            keyword_only: f(&self.keyword_only),
            neither: f(&self.neither),
        }
    }
}

/// Noreturn function names under each combination of the noreturn options.
pub type NoreturnNames = ByNoreturnTrust<HashSet<String>>;

impl NoreturnNames {
    /// Add `other`'s names under each combination.
    pub fn extend(&mut self, other: NoreturnNames) {
        self.keyword_and_stdlib.extend(other.keyword_and_stdlib);
        self.stdlib_only.extend(other.stdlib_only);
        self.keyword_only.extend(other.keyword_only);
        self.neither.extend(other.neither);
    }
}

/// Standard library functions that never return to their caller: the ISO C
/// set, plus POSIX `_exit` (POSIX.1-2024 `_exit()`), which the hosted
/// ISO C + POSIX library model covers. Trusted only under the
/// `stdlib_noreturn` contract.
///
/// `siglongjmp` is deliberately absent, so it never ends a path: it is
/// POSIX-only and, like `longjmp`, resumes the program elsewhere rather than
/// ending it (see [`NON_TERMINATING_NORETURN_FUNCTIONS`]).
const STDLIB_NORETURN_FUNCTIONS: &[&str] =
    &["abort", "exit", "_Exit", "_exit", "quick_exit", "longjmp"];

/// Noreturn functions that do **not** end the process: control resumes
/// elsewhere in the same program, so anything still allocated when they are
/// called really is leaked. Callers reasoning about *process termination*
/// (rather than merely "does not return to my caller") must exclude these --
/// see [`is_process_terminating_name`].
const NON_TERMINATING_NORETURN_FUNCTIONS: &[&str] = &["longjmp", "siglongjmp"];

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
/// carries a `_Noreturn` qualifier among its direct children.
fn has_noreturn_keyword(decl_or_def: &Node, source: &str) -> bool {
    let mut cursor = decl_or_def.walk();
    let result = decl_or_def
        .children(&mut cursor)
        .any(|c| c.kind() == "type_qualifier" && get_node_text(&c, source).trim() == "_Noreturn");
    result
}

/// The noreturn function names `settings` accepts in `root`: the
/// [`collect_noreturn_names`] set it selects.
pub fn collect_noreturn_function_names(
    root: &Node,
    source: &str,
    settings: &AnalysisSettings,
) -> HashSet<String> {
    let names = collect_noreturn_names(root, source);
    names.get(settings).clone()
}

/// Collect the names of every function in `root` recognized as noreturn by
/// the signals documented at module level, under each combination of
/// `trust_noreturn_keyword` and `stdlib_noreturn`.
pub fn collect_noreturn_names(root: &Node, source: &str) -> NoreturnNames {
    let stdlib: HashSet<String> = STDLIB_NORETURN_FUNCTIONS
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut declared: HashSet<String> = HashSet::new();

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

        if has_noreturn_keyword(&node, source) {
            declared.insert(name);
        }
    }

    let infer = |seed: HashSet<String>| {
        let mut names = seed;
        infer_terminating_definitions(root, source, &mut names);
        names
    };
    let with_declared = |mut base: HashSet<String>| {
        base.extend(declared.iter().cloned());
        base
    };
    NoreturnNames {
        keyword_and_stdlib: infer(with_declared(stdlib.clone())),
        stdlib_only: infer(stdlib),
        keyword_only: infer(with_declared(HashSet::new())),
        neither: infer(HashSet::new()),
    }
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
    // Only a definition whose body has no `return` and no `goto` can ever
    // qualify (see `body_unconditionally_terminates`), and that does not
    // change between rounds -- so the candidates are found once, and the
    // rounds only re-ask which of them now call a known terminator.
    let candidates: Vec<(Node, String)> =
        query::find_descendants_of_kind(*root, "function_definition")
            .into_iter()
            .filter(|def| body_has_no_return_or_goto(def))
            .filter_map(|def| definition_name(&def, source).map(|name| (def, name)))
            .collect();
    for _ in 0..INFERENCE_MAX_ROUNDS {
        let mut added = false;
        for (def, name) in &candidates {
            if names.contains(name) {
                continue;
            }
            if body_unconditionally_terminates(def, source, names) {
                names.insert(name.clone());
                added = true;
            }
        }
        if !added {
            break;
        }
    }
}

/// Whether `def`'s body contains no `return` and no `goto` anywhere.
fn body_has_no_return_or_goto(def: &Node) -> bool {
    def.child_by_field_name("body").is_some_and(|body| {
        query::find_first_descendant(body, |n| {
            matches!(n.kind(), "return_statement" | "goto_statement")
        })
        .is_none()
    })
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
    if !body_has_no_return_or_goto(def) {
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

/// True if `node` is an `expression_statement` calling one of the C standard
/// library's noreturn functions (`exit`, `abort`, ...). For a caller that has
/// no per-file [`collect_noreturn_function_names`] set to hand; a project's
/// own noreturn wrappers are not recognised this way.
pub fn is_stdlib_noreturn_call_statement(node: &Node, source: &str) -> bool {
    terminating_call_name(node, source)
        .is_some_and(|name| STDLIB_NORETURN_FUNCTIONS.contains(&name.as_str()))
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

    /// The names the default policy accepts in `src`.
    fn default_names(src: &str) -> HashSet<String> {
        let (tree, source) = parse(src);
        collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib
    }

    /// The names the strict policy accepts in `src`, on an environment that
    /// honors the library contract (strict policy, declared libc).
    fn strict_names(src: &str) -> HashSet<String> {
        let (tree, source) = parse(src);
        collect_noreturn_names(&tree.root_node(), &source).stdlib_only
    }

    #[test]
    fn stdlib_names_always_present() {
        for names in [
            default_names("int main(void) { return 0; }\n"),
            strict_names("int main(void) { return 0; }\n"),
        ] {
            assert!(names.contains("abort"));
            assert!(names.contains("exit"));
            assert!(names.contains("longjmp"));
        }
    }

    #[test]
    fn c11_noreturn_keyword_is_trusted_only_by_the_default_policy() {
        let src = "_Noreturn void die(void);\n";
        assert!(default_names(src).contains("die"));
        assert!(!strict_names(src).contains("die"));
    }

    #[test]
    fn a_wrapper_around_a_keyword_declared_function_follows_the_keyword() {
        let src = "_Noreturn void die(void);\nstatic void bail(void) { die(); }\n";
        assert!(default_names(src).contains("bail"));
        assert!(!strict_names(src).contains("bail"));
    }

    #[test]
    fn a_verified_body_is_proof_under_both_policies() {
        let src = "_Noreturn void die(void) { exit(1); }\n";
        assert!(default_names(src).contains("die"));
        assert!(strict_names(src).contains("die"));
    }

    #[test]
    fn posix_exit_ends_a_path_and_verifies_a_wrapper_but_siglongjmp_does_not() {
        // pure-ftpd's shape: the wrapper's GNU attribute proves nothing, but
        // its body ends in POSIX _exit(), which the hosted contract trusts.
        let src = "void _EXIT(const int status) __attribute__ ((noreturn));\n\
                   void _EXIT(const int status) { cleanup(); _exit(status); }\n\
                   static void jump(void) { siglongjmp(env, 1); }\n";
        let names = default_names(src);
        assert!(names.contains("_exit"));
        assert!(names.contains("_EXIT"));
        assert!(!names.contains("siglongjmp"));
        assert!(!names.contains("jump"));
    }

    #[test]
    fn gnu_attribute_is_proof_under_neither_policy() {
        for src in [
            "__attribute__((noreturn)) void die(void);\n",
            "void die(void) __attribute__((noreturn));\n",
        ] {
            assert!(!default_names(src).contains("die"), "{src}");
            assert!(!strict_names(src).contains("die"), "{src}");
        }
    }

    #[test]
    fn collect_noreturn_function_names_selects_by_settings() {
        use crate::settings::Preset;
        let (tree, source) = parse("_Noreturn void die(void);\n");
        let default = AnalysisSettings::preset(Preset::Default);
        let strict = AnalysisSettings::preset(Preset::Strict);
        assert!(
            collect_noreturn_function_names(&tree.root_node(), &source, &default).contains("die")
        );
        assert!(
            !collect_noreturn_function_names(&tree.root_node(), &source, &strict).contains("die")
        );
    }

    #[test]
    fn infers_noreturn_from_a_definition_that_only_exits() {
        let (tree, source) =
            parse("static void no_mem(void) { fprintf(stderr, \"oom\"); exit(1); }\n");
        let names = collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib;
        assert!(names.contains("no_mem"));
    }

    #[test]
    fn infers_through_a_chain_of_wrappers() {
        let (tree, source) = parse(
            "static void die(void) { exit(1); }\n\
             static void bail(void) { die(); }\n",
        );
        let names = collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib;
        assert!(names.contains("die"));
        assert!(names.contains("bail"));
    }

    #[test]
    fn does_not_infer_when_an_earlier_return_can_escape() {
        let (tree, source) = parse("static void maybe(int x) { if (x) return; exit(1); }\n");
        let names = collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib;
        assert!(!names.contains("maybe"));
    }

    #[test]
    fn does_not_infer_when_the_exit_is_conditional() {
        let (tree, source) = parse("static void maybe(int x) { if (x) { exit(1); } }\n");
        let names = collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib;
        assert!(!names.contains("maybe"));
    }

    #[test]
    fn does_not_infer_a_longjmp_wrapper() {
        // Genuinely noreturn, but not process-terminating: inferring it would
        // make `is_process_terminating_name` answer true and turn every
        // allocation live across it into a suppressed leak.
        let (tree, source) = parse("static void unwind(void) { longjmp(env, 1); }\n");
        let names = collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib;
        assert!(!names.contains("unwind"));
        assert!(!is_process_terminating_name("unwind", &names));
    }

    #[test]
    fn bare_noreturn_macro_prototype_is_not_proof() {
        // The seL4 shape: NORETURN expands to a GNU attribute, which is
        // proof under neither policy, and the definition's body can return.
        let src = "void NORETURN slowpath(int x);\nvoid slowpath(int x) { for (;;) {} }\n";
        assert!(!default_names(src).contains("slowpath"));
        assert!(!strict_names(src).contains("slowpath"));
    }

    #[test]
    fn nothing_is_noreturn_without_the_library_contract_or_the_keyword() {
        // The strict preset: freestanding with no libc, strict policy.
        let (tree, source) =
            parse("_Noreturn void die(void);\nstatic void bail(void) { exit(1); }\n");
        let names = collect_noreturn_names(&tree.root_node(), &source);
        assert!(names.neither.is_empty());
        assert!(names.keyword_only.contains("die"));
        assert!(!names.keyword_only.contains("exit"));
        assert!(names.stdlib_only.contains("bail"));
    }

    #[test]
    fn does_not_flag_unrelated_unknown_macro() {
        // An unresolvable macro between the return type and the declarator
        // is blanked, and must not make `foo` noreturn.
        let src = "void VISIBLE foo(void) { return; }\n";
        let (tree, source) = parse(src);
        let names = collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib;
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
        let names = collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib;
        let call_stmt =
            query::find_descendants_of_kinds(tree.root_node(), &["expression_statement"])
                .into_iter()
                .next()
                .expect("expression_statement");
        assert!(is_noreturn_call_statement(&call_stmt, &source, &names));
    }
}
