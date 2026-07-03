//! FIO39-C: Do not alternately input and output from a stream without an intervening flush or positioning call
//!
//! This rule detects alternating read/write operations on a stream without
//! an intervening fseek(), fflush(), fsetpos(), or rewind() call.
//!
//! The C Standard requires that input and output operations on update streams
//! be separated by a positioning or flush function, otherwise undefined behavior occurs.
//!
//! VIOLATIONS:
//! - fwrite() followed directly by fread() without fseek/fflush/fsetpos/rewind
//! - fread() followed directly by fwrite() without fseek/fflush/fsetpos/rewind
//! - fprintf() followed by fscanf() without intervening call
//!
//! COMPLIANT:
//! - fwrite() then fseek() then fread()
//! - fwrite() then fflush() then fread()
//! - fread() then fsetpos() then fwrite()

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio39C;

// Functions that perform output
const OUTPUT_FUNCTIONS: &[&str] = &[
    "fwrite", "fprintf", "fputs", "fputc", "putc", "fputwc", "putwc", "fputws",
];

// Functions that perform input
const INPUT_FUNCTIONS: &[&str] = &[
    "fread", "fscanf", "fgets", "fgetc", "getc", "fgetwc", "getwc", "fgetws", "ungetc", "ungetwc",
];

// Functions that reset the stream state (positioning/flush)
const POSITIONING_FUNCTIONS: &[&str] = &["fseek", "fflush", "fsetpos", "rewind"];

impl CertRule for Fio39C {
    fn rule_id(&self) -> &'static str {
        "FIO39-C"
    }

    fn description(&self) -> &'static str {
        "Do not alternately input and output from a stream without an intervening flush or positioning call"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "FIO39-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_function_body(node, source, &mut violations);
        violations
    }
}

impl Fio39C {
    fn check_function_body(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Find function definitions and check their bodies
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(body) = func.child_by_field_name("body") {
                self.analyze_compound_statement(&body, source, violations);
            }
        }
    }

    fn analyze_compound_statement(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Track the last I/O operation type: None, Input, Output
        #[derive(Clone, Copy, PartialEq)]
        enum IoOp {
            None,
            Input,
            Output,
        }

        let mut last_op = IoOp::None;
        let mut _last_op_line = 0;
        let mut last_op_name = String::new();

        // Collect all call expressions in order
        let calls = self.collect_calls_in_order(node, source);

        for (func_name, line, col) in calls {
            if POSITIONING_FUNCTIONS.contains(&func_name.as_str()) {
                // Reset state - positioning/flush allows alternation
                last_op = IoOp::None;
            } else if OUTPUT_FUNCTIONS.contains(&func_name.as_str()) {
                if last_op == IoOp::Input {
                    // Output after input without intervening positioning
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Low,
                        message: format!(
                            "Output function '{}' called after input function '{}' without intervening fseek/fflush/fsetpos/rewind",
                            func_name, last_op_name
                        ),
                        file_path: String::new(),
                        line,
                        column: col,
                        suggestion: Some(
                            "Add fseek(), fflush(), fsetpos(), or rewind() between input and output operations".to_string(),
                        ),
                        ..Default::default()
                    });
                }
                last_op = IoOp::Output;
                _last_op_line = line;
                last_op_name = func_name;
            } else if INPUT_FUNCTIONS.contains(&func_name.as_str()) {
                if last_op == IoOp::Output {
                    // Input after output without intervening positioning
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Low,
                        message: format!(
                            "Input function '{}' called after output function '{}' without intervening fseek/fflush/fsetpos/rewind",
                            func_name, last_op_name
                        ),
                        file_path: String::new(),
                        line,
                        column: col,
                        suggestion: Some(
                            "Add fseek(), fflush(), fsetpos(), or rewind() between output and input operations".to_string(),
                        ),
                        ..Default::default()
                    });
                }
                last_op = IoOp::Input;
                _last_op_line = line;
                last_op_name = func_name;
            }
        }
    }

    fn collect_calls_in_order(&self, node: &Node, source: &str) -> Vec<(String, usize, usize)> {
        let mut calls: Vec<(String, usize, usize)> =
            query::find_descendants_of_kind(*node, "call_expression")
                .into_iter()
                .filter_map(|call| {
                    call.child_by_field_name("function").map(|function| {
                        let func_name = get_node_text(&function, source);
                        let pos = call.start_position();
                        (func_name.to_string(), pos.row + 1, pos.column + 1)
                    })
                })
                .collect();
        // Sort by line number to ensure correct order
        calls.sort_by_key(|c| (c.1, c.2));
        calls
    }
}
