// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! MSC06-C: Beware of compiler optimizations
//!
//! Compilers are free to remove code with no observable effect on program
//! output, which can silently defeat security-relevant code the programmer
//! never intended to be "dead." This rule targets the two concrete,
//! statically checkable shapes from the wiki's own examples:
//!
//!   - clearing a local buffer with the library's `memset`/`ZeroMemory`
//!     ([`thread_api::library_call`]: not a project's own `memset`), neither
//!     of which is guaranteed immune to dead-store elimination, as the last
//!     meaningful thing done with that buffer before it goes out of scope --
//!     e.g. zeroing a password buffer right before `return`. The buffer is
//!     resolved to its declaration (ADR-0006): a file-scope, `static` or
//!     `extern` object outlives the function and is never flagged, and
//!     nothing may follow the clear in any block up to the one that declares
//!     it, nor may a loop lie between them (its next iteration still has the
//!     buffer). `memset_s` and `SecureZeroMemory` are guaranteed not to be
//!     optimized away and are never flagged.
//!   - an empty-body spin loop (`while (cond) { }`) whose controlling
//!     expression is a plain variable whose resolved declaration is not
//!     `volatile`, `_Atomic` or `constexpr` -- the compiler may
//!     assume the loop terminates (forward progress) and eliminate it,
//!     unlike a literal `while (1) { }` / `for (;;) { }` spin, which is left
//!     alone.
//!
//! CERT C reference:
//! <https://wiki.sei.cmu.edu/confluence/display/c/MSC06-C.+Beware+of+compiler+optimizations>

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils;
use crate::utility::cert_c::thread_api::{self, ProjectFunctions};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashSet;
use tree_sitter::Node;

const UNSAFE_CLEAR_FUNCS: &[&str] = &["memset", "ZeroMemory"];

/// Qualifiers on a spin loop's flag that keep the compiler from assuming the
/// loop ends: each access is observable (`volatile`), synchronizes
/// (`_Atomic`), or the flag is a constant the loop never waits on
/// (`constexpr`).
const SPIN_FLAG_QUALIFIERS: &[&str] = &["volatile", "_Atomic", "constexpr"];

#[derive(Default)]
pub struct Msc06C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

impl Msc06C {
    pub fn new() -> Self {
        Self::default()
    }

    /// The statement holding `node` that sits directly in a
    /// `compound_statement`, with that block, or `None` when the climb
    /// leaves `limit` first.
    fn statement_in_block<'a>(node: Node<'a>, limit: &Node) -> Option<(Node<'a>, Node<'a>)> {
        let mut stmt = node;
        while let Some(p) = stmt.parent() {
            if p.id() == limit.id() && p.kind() != "compound_statement" {
                return None;
            }
            if p.kind() == "compound_statement" {
                return Some((stmt, p));
            }
            stmt = p;
        }
        None
    }

    /// True when every statement after `stmt` in `block` references no
    /// identifier other than `dest_name` (the "touch the memory afterward"
    /// idiom, which the wiki treats as still non-compliant, references only
    /// the buffer).
    fn nothing_after(&self, stmt: &Node, block: &Node, dest_name: &str, source: &str) -> bool {
        let mut cursor = block.walk();
        let siblings: Vec<Node> = block.named_children(&mut cursor).collect();
        let Some(idx) = siblings.iter().position(|n| n == stmt) else {
            return false;
        };
        siblings[idx + 1..].iter().all(|later| {
            let mut refs = HashSet::new();
            self.collect_identifiers(later, source, &mut refs);
            refs.remove(dest_name);
            refs.is_empty()
        })
    }

    /// Collect every identifier referenced anywhere under `node`.
    fn collect_identifiers(&self, node: &Node, source: &str, out: &mut HashSet<String>) {
        for ident in query::find_descendants_of_kind(*node, "identifier") {
            out.insert(ast_utils::get_node_text(&ident, source).to_string());
        }
    }

    fn check_unsafe_clear(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*root, "call_expression") {
            let Some(func) = call.child_by_field_name("function") else {
                continue;
            };
            if func.kind() != "identifier" {
                continue;
            }
            let func_name = ast_utils::get_node_text(&func, source);
            if !UNSAFE_CLEAR_FUNCS.contains(&func_name)
                || thread_api::library_call(&call, source, self.project.borrow().as_ref())
                    != Some(func_name)
            {
                continue;
            }
            let Some(args) = call.child_by_field_name("arguments") else {
                continue;
            };
            let Some(dest) = args.named_child(0) else {
                continue;
            };
            if dest.kind() != "identifier" {
                continue;
            }
            let dest_name = ast_utils::get_node_text(&dest, source).to_string();

            // The declaration the buffer resolves to (ADR-0006). An object
            // declared at file scope, `static` or `extern` outlives the
            // function, so clearing it is no dead store; neither is clearing
            // a parameter's memory. A name nothing in reach declares is
            // judged as before, by the function's own blocks.
            let resolved = ast_utils::resolve_identifier_declarator(&dest, &dest_name, source)
                .map(|(decl, _)| decl);
            if let Some(decl) = resolved {
                if decl.kind() == "parameter_declaration"
                    || ast_utils::find_containing_function(&decl).is_none()
                    || ast_utils::declaration_has_storage_class(&decl, "static", source)
                    || ast_utils::declaration_has_storage_class(&decl, "extern", source)
                {
                    continue;
                }
            }
            let Some(function) = ast_utils::find_containing_function(&call) else {
                continue;
            };
            // The block whose end is the buffer's: the one that declares it,
            // else the function body.
            let home = resolved
                .and_then(|decl| decl.parent())
                .filter(|p| p.kind() == "compound_statement")
                .or_else(|| function.child_by_field_name("body"));
            let Some(home) = home else { continue };
            // A loop between the clear and the buffer's own block runs again
            // with the buffer still alive, so the clear is not its last use
            // before it goes out of scope.
            let in_loop = query::find_ancestor(call, |a| {
                matches!(
                    a.kind(),
                    "for_statement" | "while_statement" | "do_statement"
                )
            })
            .is_some_and(|l| {
                home.start_byte() <= l.start_byte() && l.end_byte() <= home.end_byte()
            });
            if in_loop {
                continue;
            }

            // The clear is only flagged if nothing after it, in its own
            // block and in every enclosing block up to the buffer's own,
            // references an identifier other than the buffer itself -- any
            // statement that refers to something else indicates the buffer
            // had a real use after this call, i.e. this was an
            // initialization clear, not a pre-scope-exit erase.
            let mut only_self_references = true;
            let mut at = call;
            while let Some((stmt, block)) = Self::statement_in_block(at, &function) {
                if !self.nothing_after(&stmt, &block, &dest_name, source) {
                    only_self_references = false;
                    break;
                }
                if block.id() == home.id() || block.id() == function.id() {
                    break;
                }
                at = block;
            }
            if !only_self_references {
                continue;
            }

            // The buffer must actually go out of scope at the end of this
            // function for the clear to be a dead store the compiler could
            // legally elide. It doesn't if it's a pointer parameter (the
            // caller owns the pointed-to memory, e.g. a clear/reset helper
            // like `fts5SegIterClear(Iter *p) { ...; memset(p, 0, sizeof(*p)); }`)
            // or if it escapes via `return` or an out-parameter assignment
            // (e.g. an allocator helper that zeroes then returns the buffer).
            if let Some(func) = ast_utils::find_containing_function(&call) {
                if ast_utils::is_function_parameter(&func, &dest_name, source) {
                    continue;
                }
                if self.escapes_function(&func, &dest_name, source) {
                    continue;
                }
            }

            let pos = call.start_position();
            violations.push(RuleViolation {
                rule_id: "MSC06-C".to_string(),
                severity: Severity::Medium,
                line: pos.row + 1,
                column: pos.column + 1,
                message: format!(
                    "'{}' clearing '{}' just before it goes out of scope may be removed by the compiler as a dead store",
                    func_name, dest_name
                ),
                file_path: String::new(),
                suggestion: Some(
                    "Use memset_s() or SecureZeroMemory(), which are guaranteed not to be optimized away, to clear sensitive data"
                        .to_string(),
                ),
                requires_manual_review: Some(false),
            });
        }
    }

    /// True if `dest_name` (a buffer just cleared) escapes `function` --
    /// either returned directly (`return dest_name;` / `return (T)dest_name;`)
    /// or written through a dereferenced/field/subscript out-parameter
    /// (`*out = dest_name;`, `out->field = dest_name;`), which means the
    /// cleared memory persists past the function's own scope and the clear
    /// is not the dead store MSC06-C's heuristic assumes.
    fn escapes_function(&self, function: &Node, dest_name: &str, source: &str) -> bool {
        for ret in query::find_descendants_of_kind(*function, "return_statement") {
            let mut refs = HashSet::new();
            self.collect_identifiers(&ret, source, &mut refs);
            if refs.contains(dest_name) {
                return true;
            }
        }
        for assign in query::find_descendants_of_kind(*function, "assignment_expression") {
            let Some(left) = assign.child_by_field_name("left") else {
                continue;
            };
            let Some(right) = assign.child_by_field_name("right") else {
                continue;
            };
            if !matches!(
                left.kind(),
                "unary_expression"
                    | "pointer_expression"
                    | "field_expression"
                    | "subscript_expression"
            ) {
                continue;
            }
            // The LHS must write through some *other* pointer/struct, not the
            // buffer itself -- `*(volatile char*)pwd = *(volatile char*)pwd;`
            // (the wiki's "touch the memory" idiom) has `pwd` on both sides
            // and is not an out-parameter escape.
            let mut left_refs = HashSet::new();
            self.collect_identifiers(&left, source, &mut left_refs);
            if left_refs.contains(dest_name) {
                continue;
            }
            let mut refs = HashSet::new();
            self.collect_identifiers(&right, source, &mut refs);
            if refs.contains(dest_name) {
                return true;
            }
        }
        false
    }

    fn check_spin_loop(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for while_stmt in query::find_descendants_of_kind(*root, "while_statement") {
            let Some(cond) = while_stmt.child_by_field_name("condition") else {
                continue;
            };
            // condition is a parenthesized_expression wrapping the real expr
            let Some(inner) = cond.named_child(0) else {
                continue;
            };
            if inner.kind() != "identifier" {
                continue;
            }
            let Some(body) = while_stmt.child_by_field_name("body") else {
                continue;
            };
            if body.kind() != "compound_statement" {
                continue;
            }
            let mut cursor = body.walk();
            if body.named_children(&mut cursor).count() != 0 {
                continue;
            }

            let var_name = ast_utils::get_node_text(&inner, source).to_string();
            if self.is_declared_spin_safe(&inner, source) {
                continue;
            }

            let pos = while_stmt.start_position();
            violations.push(RuleViolation {
                rule_id: "MSC06-C".to_string(),
                severity: Severity::Medium,
                line: pos.row + 1,
                column: pos.column + 1,
                message: format!(
                    "empty-body spin loop 'while ({})' controlled by a non-volatile variable may be assumed to terminate and eliminated by the compiler",
                    var_name
                ),
                file_path: String::new(),
                suggestion: Some(
                    "Declare the controlling variable volatile, or use a literal spin (while (1) { } / for (;;) { }) if an intentional infinite loop is desired"
                        .to_string(),
                ),
                requires_manual_review: Some(false),
            });
        }
    }

    /// True if `decl`'s tokens include one of [`SPIN_FLAG_QUALIFIERS`].
    fn decl_has_spin_safe_qualifier(decl: &Node, source: &str) -> bool {
        query::find_descendants_of_kind(*decl, "type_qualifier")
            .iter()
            .any(|n| SPIN_FLAG_QUALIFIERS.contains(&ast_utils::get_node_text(n, source)))
    }

    /// Whether the loop-controlling identifier at this use site resolves to
    /// a declaration (local, parameter or file scope, ADR-0006) qualified
    /// `volatile`, `_Atomic` or `constexpr`, or, when none binds it, to an
    /// `_Atomic(T) name;` the grammar misread
    /// ([`ast_utils::misread_atomic_declaration`]) earlier in a scope around
    /// the use. A name nothing in reach declares is not.
    fn is_declared_spin_safe(&self, ident: &Node, source: &str) -> bool {
        let name = ast_utils::get_node_text(ident, source);
        if let Some((decl, _)) = ast_utils::resolve_identifier_declarator(ident, name, source) {
            return Self::decl_has_spin_safe_qualifier(&decl, source);
        }
        let mut root = *ident;
        while let Some(p) = root.parent() {
            root = p;
        }
        query::find_descendants_of_kind(root, "ERROR")
            .iter()
            .any(|error| {
                ast_utils::misread_atomic_declaration(error, source).is_some_and(|declared| {
                    ast_utils::get_node_text(&declared, source) == name
                        && declared.start_byte() <= ident.start_byte()
                        && error.parent().is_some_and(|scope| {
                            scope.start_byte() <= ident.start_byte()
                                && ident.end_byte() <= scope.end_byte()
                        })
                })
            })
    }

    fn traverse(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_unsafe_clear(root, source, violations);
        self.check_spin_loop(root, source, violations);
    }
}

impl CertRule for Msc06C {
    fn rule_id(&self) -> &'static str {
        "MSC06-C"
    }

    fn description(&self) -> &'static str {
        "Beware of compiler optimizations"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "MSC06-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }
}
