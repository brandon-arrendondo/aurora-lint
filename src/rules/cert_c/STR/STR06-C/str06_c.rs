// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! STR06-C: Do not assume that strtok() leaves the parse string unchanged
//!
//! The strtok() function modifies its input string by replacing delimiters with
//! null bytes, so the string no longer holds what it did. The violation is a
//! later use of the tokenized object, and is reported there, with the strtok()
//! call as its secondary location (STR06-C/2026-10-07/1).
//!
//! This is a narrow form of the rule: it follows an environment string, an
//! object whose latest store before the call is a getenv() result, to the first
//! read of the same object (resolved by declaration) or getenv() of the same
//! variable after the call, unless a plain assignment, an overwrite or a free
//! ends the hazard first (STR06-C/2026-10-07/2, 3). A use in another arm of an
//! `if`, a `?:` or a `switch` outside any loop, or of an `#if`, is not after
//! the call on any path and is skipped; `sizeof` reads no string. A literal or
//! a getenv() result passed to strtok() with no later use is STR30-C's or
//! ENV30-C's construct, not this rule's. Known gaps, left to the rewrite: an
//! overwrite under a condition (`if (c) p = other;`) ends the hazard on every
//! path; a use earlier in the same loop body, which the next iteration
//! reaches (`for (;;) { puts(p); strtok(p, ":"); }`), is not read; and
//! neither is a `goto` back over the call.
//!
//! ## Non-compliant example:
//!
//! ```c
//! char *path = getenv("PATH");
//! char *token = strtok(path, ":");
//! printf("PATH: %s\n", path);        // VIOLATION: PATH is now "/usr/bin"
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! char *path = getenv("PATH");
//! char *path_copy = malloc(strlen(path) + 1);
//! strcpy(path_copy, path);
//! char *token = strtok(path_copy, ":");  // Modifies copy only
//! free(path_copy);
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::preproc_arms::PreprocArms;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{
    find_containing_function, get_node_text, resolve_identifier_declarator,
};
use lang_parsing_substrate::query;
use tree_sitter::Node;

/// Calls that overwrite the object their first argument names, which ends the
/// hazard (STR06-C/2026-10-07/2), or release it.
const ENDS_HAZARD: &[&str] = &[
    "free",
    "strcpy",
    "strncpy",
    "memcpy",
    "memmove",
    "memset",
    "snprintf",
    "sprintf",
    "vsnprintf",
    "vsprintf",
    "fgets",
    "gets",
];

pub struct Str06C;

impl Str06C {
    pub fn new() -> Self {
        Self
    }

    /// Get the first argument from an argument list node
    fn get_first_argument<'a>(&self, args_node: &Node<'a>) -> Option<Node<'a>> {
        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                // Skip '(' and ')' and ',' tokens
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    return Some(child);
                }
            }
        }
        None
    }

    /// The callee's name, when `node` is a call of a plain identifier.
    fn callee_name<'s>(node: &Node, source: &'s str) -> Option<&'s str> {
        if node.kind() != "call_expression" {
            return None;
        }
        let function = node.child_by_field_name("function")?;
        (function.kind() == "identifier").then(|| get_node_text(&function, source))
    }

    /// The text of a getenv() call's argument (`"PATH"`), when `node` is one.
    fn getenv_argument<'s>(&self, node: &Node, source: &'s str) -> Option<&'s str> {
        if Self::callee_name(node, source)? != "getenv" {
            return None;
        }
        let args = node.child_by_field_name("arguments")?;
        let first = self.get_first_argument(&args)?;
        Some(get_node_text(&first, source).trim())
    }

    fn strip_parens<'a>(node: Node<'a>) -> Node<'a> {
        let mut node = node;
        while node.kind() == "parenthesized_expression" {
            match node.named_child(0) {
                Some(inner) => node = inner,
                None => break,
            }
        }
        node
    }
}

impl CertRule for Str06C {
    fn rule_id(&self) -> &'static str {
        "STR06-C"
    }

    fn description(&self) -> &'static str {
        "Do not assume that strtok() leaves the parse string unchanged"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "STR06-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

/// The object or environment variable a strtok() call tokenized in place.
enum Tokenized<'a> {
    /// A variable holding an environment string, by the declarator that binds
    /// it, with the getenv() argument the string came from.
    Object {
        name: &'a str,
        declarator: usize,
        variable: &'a str,
    },
    /// `strtok(getenv("PATH"), ...)`: only a later getenv() of the same
    /// variable can read it again.
    Environment { variable: &'a str },
}

impl Str06C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let arms = std::cell::OnceCell::new();
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if Self::callee_name(&call, source) != Some("strtok") {
                continue;
            }
            let Some(first_arg) = call
                .child_by_field_name("arguments")
                .and_then(|args| self.get_first_argument(&args))
            else {
                continue;
            };
            let first_arg = Self::strip_parens(first_arg);
            let tokenized = if let Some(variable) = self.getenv_argument(&first_arg, source) {
                Tokenized::Environment { variable }
            } else if first_arg.kind() == "identifier" {
                let name = get_node_text(&first_arg, source);
                let Some((_, declarator)) = resolve_identifier_declarator(&first_arg, name, source)
                else {
                    continue;
                };
                let scope = find_containing_function(&call).unwrap_or(*node);
                match self.environment_source(&scope, &call, name, &declarator, source) {
                    Some(variable) => Tokenized::Object {
                        name,
                        declarator: declarator.start_byte(),
                        variable,
                    },
                    None => continue,
                }
            } else {
                continue;
            };
            let scope = find_containing_function(&call).unwrap_or(*node);
            let arms = arms.get_or_init(|| PreprocArms::collect(node));
            if let Some(violation) = self.later_use(&scope, &call, &tokenized, arms, source) {
                violations.push(violation);
            }
        }
    }

    /// The getenv() argument of the latest store into the object `declarator`
    /// binds before `call`, when that store is a getenv() result: its own
    /// initializer, or an assignment to a name that resolves to it.
    fn environment_source<'s>(
        &self,
        scope: &Node,
        call: &Node,
        name: &str,
        declarator: &Node,
        source: &'s str,
    ) -> Option<&'s str> {
        let mut latest: Option<(usize, Option<&'s str>)> = None;
        let mut record = |at: usize, value: Option<&'s str>| {
            if latest.is_none_or(|(prev, _)| at > prev) {
                latest = Some((at, value));
            }
        };
        if let Some(init) = std::iter::successors(Some(*declarator), |n| n.parent())
            .find(|n| n.kind() == "init_declarator")
        {
            if let Some(value) = init.child_by_field_name("value") {
                if value.start_byte() < call.start_byte() {
                    record(
                        value.start_byte(),
                        self.getenv_argument(&Self::strip_parens(value), source),
                    );
                }
            }
        }
        for assignment in query::find_descendants_of_kind(*scope, "assignment_expression") {
            if assignment.start_byte() >= call.start_byte() {
                continue;
            }
            let (Some(left), Some(right)) = (
                assignment.child_by_field_name("left"),
                assignment.child_by_field_name("right"),
            ) else {
                continue;
            };
            let left = Self::strip_parens(left);
            if left.kind() != "identifier" || get_node_text(&left, source) != name {
                continue;
            }
            if resolve_identifier_declarator(&left, name, source)
                .is_some_and(|(_, d)| d.start_byte() == declarator.start_byte())
            {
                record(
                    assignment.start_byte(),
                    self.getenv_argument(&Self::strip_parens(right), source),
                );
            }
        }
        latest.and_then(|(_, value)| value)
    }

    /// The first use after `call` of what it tokenized, reported there:
    /// a read of the same object, or a getenv() of the same variable
    /// (STR06-C/2026-10-07/3). An overwrite or a free of the object reached
    /// first ends the hazard (STR06-C/2026-10-07/2). A use no path from the
    /// call reaches, in another arm, is skipped, as is an operand of
    /// `sizeof`.
    fn later_use(
        &self,
        scope: &Node,
        call: &Node,
        tokenized: &Tokenized,
        arms: &PreprocArms,
        source: &str,
    ) -> Option<RuleViolation> {
        let variable = match tokenized {
            Tokenized::Object { variable, .. } | Tokenized::Environment { variable } => *variable,
        };
        let after = call.end_byte();
        let mut uses = query::find_descendants(*scope, |n| {
            n.start_byte() >= after && matches!(n.kind(), "identifier" | "call_expression")
        });
        uses.sort_by_key(|n| n.start_byte());
        for node in uses {
            if Self::in_other_arm(call, &node, arms) || Self::in_sizeof(&node) {
                continue;
            }
            if node.kind() == "call_expression" {
                if self.getenv_argument(&node, source) == Some(variable) {
                    return Some(self.violation(
                        &node,
                        call,
                        &format!("getenv({variable})"),
                        "reads the environment string",
                    ));
                }
                continue;
            }
            let Tokenized::Object {
                name, declarator, ..
            } = tokenized
            else {
                continue;
            };
            if get_node_text(&node, source) != *name
                || resolve_identifier_declarator(&node, name, source)
                    .is_none_or(|(_, d)| d.start_byte() != *declarator)
            {
                continue;
            }
            if Self::ends_hazard(&node, source) {
                return None;
            }
            return Some(self.violation(&node, call, &format!("'{name}'"), "is read"));
        }
        None
    }

    /// Whether `node`, after `call`, sits in an arm `call` is not in, so no
    /// path from the call reaches it: the other arm of an `if` or a `?:`, a
    /// different `case` of a `switch` when the call's case ends in a `break`
    /// or `return`, or another arm of an `#if` chain. Inside a loop the next
    /// iteration reaches the other arm, so a branch with a loop between it
    /// and the function body separates nothing. A `goto` back over the call
    /// is not read: the arms it joins are still skipped.
    fn in_other_arm(call: &Node, node: &Node, arms: &PreprocArms) -> bool {
        if arms.exclusive(call.start_byte(), node.start_byte()) {
            return true;
        }
        let contains = |outer: &Node, inner: &Node| {
            outer.start_byte() <= inner.start_byte() && inner.end_byte() <= outer.end_byte()
        };
        let Some(common) =
            std::iter::successors(node.parent(), Node::parent).find(|a| contains(a, call))
        else {
            return false;
        };
        let in_loop = std::iter::successors(Some(common), Node::parent)
            .take_while(|a| a.kind() != "function_definition")
            .any(|a| {
                matches!(
                    a.kind(),
                    "for_statement" | "while_statement" | "do_statement"
                )
            });
        if in_loop {
            return false;
        }
        let child_holding = |of: &Node| {
            (0..common.named_child_count())
                .filter_map(|i| common.named_child(i))
                .find(|c| contains(c, of))
        };
        match common.kind() {
            "if_statement" | "conditional_expression" => {
                let arm = |of: &Node| {
                    ["consequence", "alternative"].into_iter().find(|f| {
                        common
                            .child_by_field_name(f)
                            .is_some_and(|a| contains(&a, of))
                    })
                };
                matches!((arm(call), arm(node)), (Some(a), Some(b)) if a != b)
            }
            "compound_statement" => {
                let (Some(from), Some(to)) = (child_holding(call), child_holding(node)) else {
                    return false;
                };
                from.id() != to.id()
                    && from.kind() == "case_statement"
                    && to.kind() == "case_statement"
                    && Self::ends_in_jump(&from)
            }
            _ => false,
        }
    }

    /// Whether a `case` body's last statement is a `break` or `return`,
    /// looking into a braced body's last statement.
    fn ends_in_jump(case: &Node) -> bool {
        let mut last = case.named_child(case.named_child_count().saturating_sub(1));
        while let Some(block) = last.filter(|n| n.kind() == "compound_statement") {
            last = block.named_child(block.named_child_count().saturating_sub(1));
        }
        last.is_some_and(|n| matches!(n.kind(), "break_statement" | "return_statement"))
    }

    /// Whether `node` is inside the operand of `sizeof` or `_Alignof`, which
    /// reads only its type.
    fn in_sizeof(node: &Node) -> bool {
        std::iter::successors(node.parent(), Node::parent)
            .take_while(|a| !a.kind().ends_with("statement") && a.kind() != "declaration")
            .any(|a| matches!(a.kind(), "sizeof_expression" | "alignof_expression"))
    }

    /// Whether the occurrence `ident` of the tokenized object overwrites or
    /// releases it rather than reading it: the left side of a plain `=`
    /// (`p += 1` reads `p` and still points into the tokenized string), or
    /// the first argument of an overwriting call or `free`.
    fn ends_hazard(ident: &Node, source: &str) -> bool {
        let mut node = *ident;
        while let Some(parent) = node.parent() {
            if parent.kind() != "parenthesized_expression" {
                break;
            }
            node = parent;
        }
        let Some(parent) = node.parent() else {
            return false;
        };
        match parent.kind() {
            "assignment_expression" => {
                parent
                    .child_by_field_name("left")
                    .is_some_and(|left| left.id() == node.id())
                    && parent
                        .child_by_field_name("operator")
                        .is_some_and(|op| get_node_text(&op, source) == "=")
            }
            "argument_list" => {
                let first = (0..parent.child_count())
                    .filter_map(|i| parent.child(i))
                    .find(|c| !matches!(c.kind(), "(" | ")" | ","));
                first.is_some_and(|first| first.id() == node.id())
                    && parent.parent().is_some_and(|call| {
                        Self::callee_name(&call, source)
                            .is_some_and(|callee| ENDS_HAZARD.contains(&callee))
                    })
            }
            _ => false,
        }
    }

    fn violation(&self, at: &Node, call: &Node, what: &str, how: &str) -> RuleViolation {
        RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: format!(
                "{what} {how} after strtok() at line {} tokenized it in place; strtok() replaced its delimiters with null bytes, so it no longer holds the original string.",
                call.start_position().row + 1
            ),
            file_path: String::new(),
            line: at.start_position().row + 1,
            column: at.start_position().column + 1,
            suggestion: Some(
                "Tokenize a copy of the string (for example from strdup()) and keep the original unchanged."
                    .to_string(),
            ),
            ..Default::default()
        }
    }
}
