// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! MSC22-C: Use the setjmp(), longjmp() facility securely
//!
//! This rule targets the two statically checkable misuses from the wiki's
//! own examples:
//!
//!   - `setjmp()` invoked outside one of the contexts the C Standard
//!     permits: the entire controlling expression of an `if`/`while`/`for`/
//!     `do`, one operand of `==`/`!=` against an integer constant where that
//!     comparison is the entire controlling expression, the operand of `!`
//!     as the entire controlling expression, or the entire expression of an
//!     expression statement. Using it as a declaration initializer (`int i =
//!     setjmp(buf);`) is a common violation of this.
//!   - a non-`volatile` local read inside the "longjmp returned" branch of
//!     an `if (setjmp(...) ...)` whose value is also reassigned elsewhere in
//!     the function -- its value is indeterminate after `longjmp()` unless
//!     it's `volatile`-qualified.
//!
//! Note: a third real misuse from the wiki -- calling `longjmp()` after the
//! function that called the matching `setjmp()` has already returned --
//! requires interprocedural call-stack-liveness reasoning this rule does
//! not attempt.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/MSC22-C.+Use+the+setjmp%28%29%2C+longjmp%28%29+facility+securely

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Msc22C;

impl Msc22C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc22C
    }

    fn is_setjmp_call(&self, call: &Node, source: &str) -> bool {
        call.child_by_field_name("function")
            .map(|f| f.kind() == "identifier" && ast_utils::get_node_text(&f, source) == "setjmp")
            .unwrap_or(false)
    }

    /// Whether `call` (a setjmp() call) appears in one of the contexts the
    /// C Standard permits.
    fn is_allowed_context(&self, call: &Node, source: &str) -> bool {
        let Some(parent) = call.parent() else {
            return false;
        };

        let effective = match parent.kind() {
            "expression_statement" => return true,
            "binary_expression" => {
                let Some(op) = parent.child(1) else {
                    return false;
                };
                let op_text = ast_utils::get_node_text(&op, source);
                if op_text != "==" && op_text != "!=" {
                    return false;
                }
                let other = if parent.child_by_field_name("left") == Some(*call) {
                    parent.child_by_field_name("right")
                } else {
                    parent.child_by_field_name("left")
                };
                if other.map(|o| o.kind() != "number_literal").unwrap_or(true) {
                    return false;
                }
                parent
            }
            "unary_expression" => {
                let Some(op) = parent.child(0) else {
                    return false;
                };
                if ast_utils::get_node_text(&op, source) != "!" {
                    return false;
                }
                parent
            }
            _ => *call,
        };

        let Some(paren) = effective.parent() else {
            return false;
        };
        if paren.kind() != "parenthesized_expression" {
            return false;
        }
        let Some(stmt) = paren.parent() else {
            return false;
        };
        matches!(
            stmt.kind(),
            "if_statement" | "while_statement" | "do_statement" | "for_statement"
        )
    }

    fn check_context(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*root, "call_expression") {
            if !self.is_setjmp_call(&call, source) {
                continue;
            }
            if self.is_allowed_context(&call, source) {
                continue;
            }
            let pos = call.start_position();
            violations.push(RuleViolation {
                rule_id: "MSC22-C".to_string(),
                severity: Severity::Low,
                line: pos.row + 1,
                column: pos.column + 1,
                message: "setjmp() used outside a context the C Standard permits (e.g. as a declaration initializer) -- undefined behavior".to_string(),
                file_path: String::new(),
                suggestion: Some(
                    "Use setjmp() only as the entire controlling expression of an if/while/for/do (optionally compared to an integer constant, or negated), or as the entire expression of an expression statement"
                        .to_string(),
                ),
                requires_manual_review: Some(false),
            });
        }
    }

    /// Resolves `ident`'s binding via the scope/shadowing-aware declaration
    /// lookup (not a flat function-body scan, which could conflate two
    /// nested blocks with a shadowed name of the same spelling) and checks
    /// whether that declaration's type text mentions `volatile`.
    fn is_declared_volatile(&self, ident: &Node, var_name: &str, source: &str) -> bool {
        let Some(decl) =
            ast_utils::find_enclosing_declaration_for_identifier(ident, var_name, source)
        else {
            return false;
        };
        query::find_descendants_of_kind(decl, "type_qualifier")
            .iter()
            .any(|n| ast_utils::get_node_text(n, source) == "volatile")
    }

    fn reassigned_outside(
        &self,
        func: &Node,
        var_name: &str,
        exclude: &Node,
        source: &str,
    ) -> bool {
        query::find_descendants_of_kind(*func, "assignment_expression")
            .iter()
            .any(|assign| {
                if assign.start_byte() >= exclude.start_byte()
                    && assign.end_byte() <= exclude.end_byte()
                {
                    return false;
                }
                assign
                    .child_by_field_name("left")
                    .map(|l| {
                        l.kind() == "identifier" && ast_utils::get_node_text(&l, source) == var_name
                    })
                    .unwrap_or(false)
            })
    }

    fn check_stale_locals(&self, func: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for if_stmt in query::find_descendants_of_kind(*func, "if_statement") {
            let Some(cond) = if_stmt.child_by_field_name("condition") else {
                continue;
            };
            let has_setjmp = query::find_descendants_of_kind(cond, "call_expression")
                .iter()
                .any(|c| self.is_setjmp_call(c, source));
            if !has_setjmp {
                continue;
            }

            let mut branches = Vec::new();
            if let Some(c) = if_stmt.child_by_field_name("consequence") {
                branches.push(c);
            }
            if let Some(a) = if_stmt.child_by_field_name("alternative") {
                branches.push(a);
            }

            let mut flagged: HashSet<String> = HashSet::new();
            for branch in branches {
                for ident in query::find_descendants_of_kind(branch, "identifier") {
                    // Skip identifiers that are themselves assignment targets
                    // within the branch (writes, not reads).
                    if ident
                        .parent()
                        .map(|p| {
                            p.kind() == "assignment_expression"
                                && p.child_by_field_name("left") == Some(ident)
                        })
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    let name = ast_utils::get_node_text(&ident, source).to_string();
                    if flagged.contains(&name) {
                        continue;
                    }
                    if self.is_declared_volatile(&ident, &name, source) {
                        continue;
                    }
                    if !self.reassigned_outside(func, &name, &if_stmt, source) {
                        continue;
                    }

                    flagged.insert(name.clone());
                    let pos = ident.start_position();
                    violations.push(RuleViolation {
                        rule_id: "MSC22-C".to_string(),
                        severity: Severity::Low,
                        line: pos.row + 1,
                        column: pos.column + 1,
                        message: format!(
                            "'{}' is read here after a possible longjmp() return, but it is reassigned elsewhere and not declared volatile -- its value is indeterminate",
                            name
                        ),
                        file_path: String::new(),
                        suggestion: Some(format!(
                            "Declare '{}' volatile if its value must survive a longjmp() back into this branch",
                            name
                        )),
                        requires_manual_review: Some(false),
                    });
                }
            }
        }
    }

    fn traverse(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_context(root, source, violations);
        for func in query::find_descendants_of_kind(*root, "function_definition") {
            self.check_stale_locals(&func, source, violations);
        }
    }
}

impl CertRule for Msc22C {
    fn rule_id(&self) -> &'static str {
        "MSC22-C"
    }

    fn description(&self) -> &'static str {
        "Use the setjmp(), longjmp() facility securely"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "MSC22-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
