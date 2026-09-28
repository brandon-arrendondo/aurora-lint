// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! EXP47-C: Do not call va_arg with an argument of the incorrect type
//!
//! This rule detects when va_arg is called with a type that doesn't match
//! the type of the actual argument after default argument promotions.
//! Common violations include using va_arg with char, short, or float types
//! which undergo promotion to int/unsigned int or double when passed.
//!
//! CERT C reference:
//! <https://wiki.sei.cmu.edu/confluence/display/c/EXP47-C.+Do+not+call+va_arg+with+an+argument+of+the+incorrect+type>

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

/// `va_arg`, or the builtin `<stdarg.h>` defines it as.
fn is_va_arg_name(name: &str) -> bool {
    matches!(name, "va_arg" | "__builtin_va_arg")
}

/// A type argument as one line of words: comments removed and whitespace,
/// newlines included, collapsed to single spaces.
fn normalize_type_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("/*") {
            rest = after.find("*/").map_or("", |end| &after[end + 2..]);
            out.push(' ');
        } else if let Some(after) = rest.strip_prefix("//") {
            rest = after.find('\n').map_or("", |end| &after[end..]);
            out.push(' ');
        } else {
            let c = rest.chars().next().unwrap_or_default();
            out.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[derive(Debug)]
pub struct Exp47C;

/// Information about a variadic function
#[derive(Debug, Clone)]
struct VariadicFuncInfo {
    /// Number of fixed parameters (before ...)
    fixed_param_count: usize,
    /// Number of va_arg calls in the function body
    va_arg_count: usize,
}

impl Exp47C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Exp47C
    }

    /// Check if a type undergoes default argument promotion
    /// Types that promote:
    /// - char, signed char, unsigned char -> int
    /// - short, unsigned short -> int (or unsigned int if larger)
    /// - float -> double
    ///
    /// `type_text` is normalized (`normalize_type_text`). The type is read by
    /// its set of specifiers, not its spelling: `short signed` is `short`,
    /// qualifiers are ignored, and a pointer, array or function type, or any
    /// other word (a typedef name, `long`), is not one of these.
    fn is_promoted_type(&self, type_text: &str) -> Option<&'static str> {
        if type_text.contains(['*', '(', '[']) {
            return None;
        }
        let words: Vec<&str> = type_text
            .split_whitespace()
            .filter(|w| !matches!(*w, "const" | "volatile" | "restrict" | "_Atomic"))
            .collect();
        if words.iter().any(|w| {
            !matches!(
                *w,
                "signed" | "unsigned" | "char" | "short" | "int" | "float"
            )
        }) {
            return None;
        }
        let has = |w: &str| words.contains(&w);
        if has("char") && !has("short") && !has("int") && !has("float") {
            return Some("int");
        }
        if has("short") && !has("char") && !has("float") {
            return Some(if has("unsigned") {
                "int or unsigned int"
            } else {
                "int"
            });
        }
        if words == ["float"] {
            return Some("double");
        }
        None
    }

    /// Extract the type argument from a va_arg call
    fn extract_va_arg_type(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() != "call_expression" {
            return None;
        }
        let function = node.child_by_field_name("function")?;
        if !is_va_arg_name(get_node_text(&function, source).trim()) {
            return None;
        }
        let arguments = node.child_by_field_name("arguments")?;

        // The type is everything between the first `,` and the closing `)`.
        // A multi-word type such as `unsigned char` is not an expression, so it
        // parses as an identifier followed by an ERROR node, not as one child.
        let mut cursor = arguments.walk();
        let children: Vec<Node> = arguments.children(&mut cursor).collect();
        let comma = children.iter().position(|c| c.kind() == ",")?;
        let type_nodes: Vec<&Node> = children[comma + 1..]
            .iter()
            .filter(|c| c.kind() != ")")
            .collect();
        let (first, last) = (type_nodes.first()?, type_nodes.last()?);
        let type_text = normalize_type_text(&source[first.start_byte()..last.end_byte()]);
        (!type_text.is_empty()).then_some(type_text)
    }

    fn push_violation(
        &self,
        type_text: &str,
        correct_type: &str,
        row: usize,
        column: usize,
        violations: &mut Vec<RuleViolation>,
    ) {
        violations.push(RuleViolation {
            rule_id: "EXP47-C".to_string(),
            severity: Severity::Medium,
            line: row + 1,
            column: column + 1,
            message: format!(
                "va_arg called with type '{}' which undergoes default argument promotion; use '{}' instead",
                type_text, correct_type
            ),
            file_path: String::new(),
            suggestion: Some(format!(
                "Change va_arg type to '{}' and cast the result if needed: ({})va_arg(ap, {})",
                correct_type, type_text, correct_type
            )),
            requires_manual_review: Some(false),
        });
    }

    /// Check a va_arg call for incorrect type usage
    fn check_va_arg_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(type_text) = self.extract_va_arg_type(node, source) {
            if let Some(correct_type) = self.is_promoted_type(&type_text) {
                let start = node.start_position();
                self.push_violation(
                    &type_text,
                    correct_type,
                    start.row,
                    start.column,
                    violations,
                );
            }
        }
    }

    /// Visit every va_arg call once, plus each macro's replacement list.
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |n| {
            matches!(
                n.kind(),
                "call_expression" | "preproc_def" | "preproc_function_def"
            )
        }) {
            if n.kind() == "call_expression" {
                self.check_va_arg_call(&n, source, violations);
            } else {
                self.check_macro_body(&n, source, violations);
            }
        }
    }

    /// A macro's replacement list is unparsed `preproc_arg` text, so a
    /// `va_arg` written there has no call_expression to visit. Read it from
    /// the text, reporting each occurrence at its own position. A comment in
    /// the list splits it into several nodes, so the list is read as the span
    /// from its first `preproc_arg` to the end of the directive.
    fn check_macro_body(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let Some(first) = query::find_descendants_of_kind(*node, "preproc_arg")
            .into_iter()
            .min_by_key(|n| n.start_byte())
        else {
            return;
        };
        let offset = first.start_byte();
        let text = &source[offset..node.end_byte()];
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find("va_arg(") {
            let at = search_from + pos;
            search_from = at + "va_arg(".len();
            // The whole identifier ending here must be a va_arg spelling: a
            // longer name such as `my_va_arg` is a different function.
            let start = text[..at]
                .rfind(|c: char| !(c.is_alphanumeric() || c == '_'))
                .map_or(0, |i| i + 1);
            if !is_va_arg_name(&text[start..at + "va_arg".len()]) {
                continue;
            }
            let args = &text[search_from..];
            let Some(comma) = args.find(',') else {
                continue;
            };
            let Some(close) = args[comma + 1..].find(')') else {
                continue;
            };
            let type_text = normalize_type_text(&args[comma + 1..comma + 1 + close]);
            if let Some(correct_type) = self.is_promoted_type(&type_text) {
                let before = &source[..offset + start];
                let row = before.matches('\n').count();
                let column = before.len() - before.rfind('\n').map_or(0, |i| i + 1);
                self.push_violation(&type_text, correct_type, row, column, violations);
            }
        }
    }

    /// Collect information about variadic functions defined in the source
    fn collect_variadic_functions(
        &self,
        node: &Node,
        source: &str,
        funcs: &mut HashMap<String, VariadicFuncInfo>,
    ) {
        for n in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(declarator) = n.child_by_field_name("declarator") {
                // Check if this is a variadic function
                let decl_text = get_node_text(&declarator, source);
                if decl_text.contains("...") {
                    // Extract function name
                    if let Some(func_name) = self.extract_function_name(&declarator, source) {
                        // Count fixed parameters
                        let fixed_params = self.count_fixed_params(&declarator, source);
                        // Count UNCONDITIONAL va_arg calls in body
                        let va_arg_count = if let Some(body) = n.child_by_field_name("body") {
                            self.count_unconditional_va_arg_calls(&body, source)
                        } else {
                            0
                        };

                        funcs.insert(
                            func_name,
                            VariadicFuncInfo {
                                fixed_param_count: fixed_params,
                                va_arg_count,
                            },
                        );
                    }
                }
            }
        }
    }

    /// Extract function name from declarator
    fn extract_function_name(&self, declarator: &Node, source: &str) -> Option<String> {
        if declarator.kind() == "function_declarator" {
            if let Some(name_node) = declarator.child_by_field_name("declarator") {
                return Some(get_node_text(&name_node, source).trim().to_string());
            }
        }
        // Try children
        let mut cursor = declarator.walk();
        for child in declarator.children(&mut cursor) {
            if let Some(name) = self.extract_function_name(&child, source) {
                return Some(name);
            }
        }
        None
    }

    /// Count fixed parameters (non-variadic)
    fn count_fixed_params(&self, declarator: &Node, source: &str) -> usize {
        let text = get_node_text(declarator, source);
        // Find the parameter list
        // Pattern: func(param1, param2, ...) or func(...)
        if let Some(start) = text.find('(') {
            if let Some(ellipsis_pos) = text.find("...") {
                let params_text = &text[start + 1..ellipsis_pos];
                // Remove trailing comma and whitespace
                let params_text = params_text.trim().trim_end_matches(',').trim();
                if params_text.is_empty() {
                    return 0;
                }
                // Number of fixed params = number of commas + 1
                // e.g., "size_t num_vargs" has 0 commas -> 1 param
                // e.g., "const char *cp, size_t n" has 1 comma -> 2 params
                return params_text.matches(',').count() + 1;
            }
        }
        0
    }

    /// Count UNCONDITIONAL va_arg calls in a function body
    /// Only counts va_arg calls that are not nested inside if/while/for/switch statements
    fn count_unconditional_va_arg_calls(&self, body: &Node, source: &str) -> usize {
        let mut count = 0;
        self.count_va_arg_at_depth(body, source, 0, &mut count);
        count
    }

    /// Recursively count va_arg calls, only counting those at conditional depth 0
    fn count_va_arg_at_depth(
        &self,
        node: &Node,
        source: &str,
        conditional_depth: usize,
        count: &mut usize,
    ) {
        // Check if this node contains a va_arg call (AST-based detection)
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source).trim().to_string();
                if func_name == "va_arg" && conditional_depth == 0 {
                    *count += 1;
                    return; // Found a va_arg, don't recurse into its children
                }
            }
        }

        // Text-based fallback for macro expansion cases - only for leaf-ish nodes
        // Only check if this specific statement/expression contains va_arg and has no
        // conditional children (to avoid double counting)
        if conditional_depth == 0
            && matches!(
                node.kind(),
                "expression_statement" | "declaration" | "init_declarator"
            )
        {
            let node_text = get_node_text(node, source);
            if node_text.contains("va_arg(") && !self.has_conditional_children(node) {
                *count += node_text.matches("va_arg(").count();
                return; // Don't recurse further
            }
        }

        // Increase depth when entering conditional structures
        let new_depth = if matches!(
            node.kind(),
            "if_statement"
                | "while_statement"
                | "for_statement"
                | "switch_statement"
                | "do_statement"
        ) {
            conditional_depth + 1
        } else {
            conditional_depth
        };

        // Recurse into children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.count_va_arg_at_depth(&child, source, new_depth, count);
        }
    }

    /// Check if a node has any conditional statement children
    fn has_conditional_children(&self, node: &Node) -> bool {
        query::find_first_descendant(*node, |n| {
            matches!(
                n.kind(),
                "if_statement"
                    | "while_statement"
                    | "for_statement"
                    | "switch_statement"
                    | "do_statement"
            )
        })
        .is_some()
    }

    /// Check calls to variadic functions
    fn check_variadic_calls(
        &self,
        node: &Node,
        source: &str,
        funcs: &HashMap<String, VariadicFuncInfo>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = n.child_by_field_name("function") {
                let func_name = get_node_text(&function, source).trim().to_string();

                if let Some(info) = funcs.get(&func_name) {
                    // Count actual arguments passed
                    let actual_args = if let Some(args) = n.child_by_field_name("arguments") {
                        self.count_arguments(&args)
                    } else {
                        0
                    };

                    // Check if enough variadic arguments are passed
                    let variadic_args_passed = actual_args.saturating_sub(info.fixed_param_count);
                    if variadic_args_passed < info.va_arg_count {
                        violations.push(RuleViolation {
                            rule_id: "EXP47-C".to_string(),
                            severity: Severity::Medium,
                            line: n.start_position().row + 1,
                            column: n.start_position().column + 1,
                            message: format!(
                                "Call to variadic function '{}' passes {} variadic argument(s) but function uses va_arg {} time(s)",
                                func_name, variadic_args_passed, info.va_arg_count
                            ),
                            file_path: String::new(),
                            suggestion: Some(format!(
                                "Pass at least {} variadic argument(s) to match va_arg usage in '{}'",
                                info.va_arg_count, func_name
                            )),
                            requires_manual_review: Some(false),
                        });
                    }
                }
            }
        }
    }

    /// Count arguments in an argument list
    fn count_arguments(&self, args: &Node) -> usize {
        let mut count = 0;
        let mut cursor = args.walk();
        for child in args.children(&mut cursor) {
            // Skip parentheses and commas
            if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                count += 1;
            }
        }
        count
    }
}

impl CertRule for Exp47C {
    fn rule_id(&self) -> &'static str {
        "EXP47-C"
    }

    fn description(&self) -> &'static str {
        "Do not call va_arg with an argument of the incorrect type"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "EXP47-C"
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First, collect information about variadic functions defined in the source
        let mut variadic_funcs = HashMap::new();
        self.collect_variadic_functions(root, source, &mut variadic_funcs);

        // Check for incorrect va_arg type usage
        self.traverse(root, source, &mut violations);

        // Check calls to variadic functions for insufficient arguments
        self.check_variadic_calls(root, source, &variadic_funcs, &mut violations);

        violations
    }
}
