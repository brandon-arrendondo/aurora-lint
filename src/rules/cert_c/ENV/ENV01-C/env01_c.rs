// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! ENV01-C: Do not make assumptions about the size of an environment variable
//!
//! The wiki's noncompliant example is `strcpy(path, getenv("PATH"))`: the
//! value of an environment variable has no bound the program controls, so
//! copying it with a function that stops only at the terminator assumes a
//! size that nothing guarantees. The compliant solutions size the copy from
//! `strlen()` of the value, or `strdup()` it.
//!
//! What is reported is exactly that flow: a `getenv()`-family result -- the
//! call itself, or a local the call was stored in earlier in the same
//! function -- reaching an unbounded copy (`strcpy`, `strcat`, `stpcpy`,
//! `sprintf`, `wcscpy`, `wcscat`). When the source is a local, the
//! destination must be an array with a declared size: the wiki's first
//! compliant solution is `path = malloc(strlen(temp) + 1); strcpy(path,
//! temp);`, the same copy into a buffer sized from the value, and the array
//! is what carries the assumption. A call in argument position is the
//! noncompliant example itself and is reported whatever the destination --
//! nothing could have measured a value that was never stored.
//!
//! What is deliberately NOT reported: a fixed-size buffer on its own. An
//! earlier revision flagged every array whose size expression contained the
//! substring `MAX`, "may be used with environment variable", without looking
//! for one -- 570 of the 572 labels it accumulated across eleven real-world
//! oracles were false, every one of them a `PATH_MAX`/`NI_MAXHOST`/`MAX_PATH`
//! buffer in a function that never touched the environment. A
//! finding that names a construct absent from the line is a misfire
//! (ADR-0005), so that check is gone rather than narrowed.
//!
//! CERT C reference:
//! <https://wiki.sei.cmu.edu/confluence/display/c/ENV01-C.+Do+not+make+assumptions+about+the+size+of+an+environment+variable>

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{
    get_identifier_from_declarator, get_node_text, resolve_identifier_declarator,
};
use crate::utility::cert_c::declarator_utils::is_array_declarator;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

/// Functions whose return value is an environment variable's text.
const ENV_READERS: &[&str] = &["getenv", "secure_getenv", "_wgetenv"];

/// Copies that stop at the terminator and nowhere else. The index is the
/// first argument position a source string can occupy: `strcpy(dst, src)`
/// reads its source at 1, `sprintf(dst, fmt, ...)` from 2 on.
const UNBOUNDED_COPIES: &[(&str, usize)] = &[
    ("strcpy", 1),
    ("strcat", 1),
    ("stpcpy", 1),
    ("wcscpy", 1),
    ("wcscat", 1),
    ("sprintf", 2),
];

#[derive(Debug)]
pub struct Env01C;

impl Env01C {
    pub fn new() -> Self {
        Env01C
    }

    fn check_function(&self, func: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let Some(body) = func.child_by_field_name("body") else {
            return;
        };
        let bound = env_bound_locals(&body, source);

        for call in query::find_descendants_of_kind(body, "call_expression") {
            let Some(function) = call.child_by_field_name("function") else {
                continue;
            };
            let callee = get_node_text(&function, source);
            let Some(&(_, first_source)) =
                UNBOUNDED_COPIES.iter().find(|(name, _)| *name == callee)
            else {
                continue;
            };
            let Some(args) = call.child_by_field_name("arguments") else {
                continue;
            };
            let args: Vec<Node> = args.named_children(&mut args.walk()).collect();
            let Some(dst) = args.first() else {
                continue;
            };

            for arg in args.iter().skip(first_source) {
                let Some(origin) = env_origin(arg, &bound, source) else {
                    continue;
                };
                if origin.via_local && !is_fixed_size_array(dst, source) {
                    continue;
                }
                violations.push(RuleViolation {
                    rule_id: "ENV01-C".to_string(),
                    severity: Severity::High,
                    line: call.start_position().row + 1,
                    column: call.start_position().column + 1,
                    message: format!(
                        "{}() copies {} into '{}' with no bound on the environment variable's length",
                        callee,
                        origin.text,
                        get_node_text(dst, source)
                    ),
                    file_path: String::new(),
                    suggestion: Some(
                        "Size the destination from strlen() of the getenv() result, or strdup() it"
                            .to_string(),
                    ),
                    requires_manual_review: Some(false),
                });
                break;
            }
        }
    }
}

/// Locals this function binds to an environment reader, keyed by name, with
/// the byte offset of the binding so a use that precedes it is not credited
/// to it. Flow-insensitive beyond that: a later rebinding to something else
/// is not modelled.
fn env_bound_locals(body: &Node, source: &str) -> HashMap<String, usize> {
    let mut bound = HashMap::new();
    for n in query::find_descendants_of_kinds(*body, &["init_declarator", "assignment_expression"])
    {
        let (target, value) = match n.kind() {
            "init_declarator" => (
                n.child_by_field_name("declarator"),
                n.child_by_field_name("value"),
            ),
            _ => (
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            ),
        };
        let (Some(target), Some(value)) = (target, value) else {
            continue;
        };
        if !is_env_reader_call(&strip_casts_and_parens(value), source) {
            continue;
        }
        let name = match target.kind() {
            "identifier" => get_node_text(&target, source).to_string(),
            _ => get_identifier_from_declarator(&target, source),
        };
        if !name.is_empty() {
            bound.entry(name).or_insert(n.start_byte());
        }
    }
    bound
}

/// Why `arg` is an environment variable's text.
struct EnvOrigin {
    text: String,
    /// The value went through a local first, so the destination could have
    /// been sized from it.
    via_local: bool,
}

/// Why `arg` is an environment variable's text, if it is: the reader call
/// itself, or a local bound to one earlier in the function.
fn env_origin(arg: &Node, bound: &HashMap<String, usize>, source: &str) -> Option<EnvOrigin> {
    let expr = strip_casts_and_parens(*arg);
    if is_env_reader_call(&expr, source) {
        let callee = expr.child_by_field_name("function")?;
        return Some(EnvOrigin {
            text: format!("the {}() result", get_node_text(&callee, source)),
            via_local: false,
        });
    }
    if expr.kind() == "identifier" {
        let name = get_node_text(&expr, source);
        if bound.get(name).is_some_and(|&at| at < expr.start_byte()) {
            return Some(EnvOrigin {
                text: format!("'{}' (a getenv() result)", name),
                via_local: true,
            });
        }
    }
    None
}

/// `dst` names a variable declared as an array with a size of its own --
/// the declaration is resolved through scope, not matched by name
/// (ADR-0006). A pointer, a parameter (`char out[]` has no size here), a
/// field or any other expression is not one.
fn is_fixed_size_array(dst: &Node, source: &str) -> bool {
    let expr = strip_casts_and_parens(*dst);
    if expr.kind() != "identifier" {
        return false;
    }
    let name = get_node_text(&expr, source);
    resolve_identifier_declarator(&expr, name, source).is_some_and(|(decl, declarator)| {
        decl.kind() != "parameter_declaration" && is_array_declarator(&declarator)
    })
}

fn is_env_reader_call(node: &Node, source: &str) -> bool {
    node.kind() == "call_expression"
        && node
            .child_by_field_name("function")
            .is_some_and(|f| ENV_READERS.contains(&get_node_text(&f, source)))
}

fn strip_casts_and_parens<'a>(mut node: Node<'a>) -> Node<'a> {
    loop {
        let inner = match node.kind() {
            "parenthesized_expression" => node.named_child(0),
            "cast_expression" => node.child_by_field_name("value"),
            _ => None,
        };
        match inner {
            Some(n) => node = n,
            None => return node,
        }
    }
}

impl Default for Env01C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Env01C {
    fn rule_id(&self) -> &'static str {
        "ENV01-C"
    }

    fn description(&self) -> &'static str {
        "Do not make assumptions about the size of an environment variable"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ENV01-C"
    }

    fn scan(&self, root_node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for func in query::find_descendants_of_kind(*root_node, "function_definition") {
            self.check_function(&func, source, violations);
        }
    }
}
