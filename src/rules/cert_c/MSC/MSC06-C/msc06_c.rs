// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! MSC06-C: Beware of compiler optimizations
//!
//! Compilers are free to remove code with no observable effect on program
//! output, which can silently defeat security-relevant code the programmer
//! never intended to be "dead." This rule targets the two concrete,
//! statically checkable shapes from the wiki's own examples:
//!
//!   - clearing a local buffer with `memset`/`ZeroMemory` (neither of which
//!     is guaranteed immune to dead-store elimination) as the last
//!     meaningful thing done with that buffer before it goes out of scope --
//!     e.g. zeroing a password buffer right before `return`. `memset_s` and
//!     `SecureZeroMemory` are guaranteed not to be optimized away and are
//!     never flagged.
//!   - an empty-body spin loop (`while (cond) { }`) whose controlling
//!     expression is a plain, non-`volatile` variable -- the compiler may
//!     assume the loop terminates (forward progress) and eliminate it,
//!     unlike a literal `while (1) { }` / `for (;;) { }` spin, which is left
//!     alone.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/MSC06-C.+Beware+of+compiler+optimizations

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

const UNSAFE_CLEAR_FUNCS: &[&str] = &["memset", "ZeroMemory"];

#[derive(Debug)]
pub struct Msc06C;

impl Msc06C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc06C
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
            if !UNSAFE_CLEAR_FUNCS.contains(&func_name) {
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

            // Find the statement containing this call, and the compound
            // statement it's a direct child of.
            let mut stmt = call;
            while let Some(p) = stmt.parent() {
                if p.kind() == "compound_statement" {
                    break;
                }
                stmt = p;
            }
            let Some(block) = stmt.parent() else { continue };
            if block.kind() != "compound_statement" {
                continue;
            }

            let mut cursor = block.walk();
            let siblings: Vec<Node> = block.named_children(&mut cursor).collect();
            let Some(idx) = siblings.iter().position(|n| *n == stmt) else {
                continue;
            };

            // The clear is only flagged if every statement following it in
            // this block references no identifier other than the buffer
            // itself (covers the "touch the memory afterward" idiom, which
            // the wiki treats as still non-compliant) -- any statement that
            // refers to something else indicates the buffer had a real use
            // after this call, i.e. this was an initialization clear, not a
            // pre-scope-exit erase.
            let mut only_self_references = true;
            for later in &siblings[idx + 1..] {
                let mut refs = HashSet::new();
                self.collect_identifiers(later, source, &mut refs);
                refs.remove(&dest_name);
                if !refs.is_empty() {
                    only_self_references = false;
                    break;
                }
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
            if self.is_declared_volatile(&inner, source) {
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

    /// True if `decl`'s tokens include a `volatile` type qualifier.
    fn decl_has_volatile(decl: &Node, source: &str) -> bool {
        query::find_descendants_of_kind(*decl, "type_qualifier")
            .iter()
            .any(|n| ast_utils::get_node_text(n, source) == "volatile")
    }

    /// Resolve whether the loop-controlling identifier at this use site is
    /// declared `volatile`. Scope- and shadowing-aware via
    /// `find_enclosing_declaration_for_identifier` for locals; falls back to
    /// a file-scope (global) declaration scan, since that helper
    /// intentionally only walks enclosing `compound_statement` blocks and
    /// never resolves to file-scope declarations.
    fn is_declared_volatile(&self, ident: &Node, source: &str) -> bool {
        let name = ast_utils::get_node_text(ident, source);
        if let Some(decl) =
            ast_utils::find_enclosing_declaration_for_identifier(ident, name, source)
        {
            return Self::decl_has_volatile(&decl, source);
        }

        let mut top = *ident;
        while let Some(p) = top.parent() {
            top = p;
        }
        for i in 0..top.child_count() {
            let Some(decl) = top.child(i) else { continue };
            if decl.kind() != "declaration" {
                continue;
            }
            let has_name = query::find_descendants_of_kind(decl, "identifier")
                .iter()
                .any(|n| ast_utils::get_node_text(n, source) == name);
            if has_name && Self::decl_has_volatile(&decl, source) {
                return true;
            }
        }
        false
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

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
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
}
