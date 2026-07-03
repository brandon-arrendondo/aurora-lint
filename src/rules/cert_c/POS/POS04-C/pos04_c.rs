//! POS04-C: Avoid using PTHREAD_MUTEX_NORMAL type mutex locks
//!
//! This rule detects usage of PTHREAD_MUTEX_NORMAL or PTHREAD_MUTEX_DEFAULT
//! mutex types, which have undefined behavior in certain scenarios.
//!
//! VIOLATIONS:
//! - pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL)
//! - pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_DEFAULT)
//!
//! COMPLIANT:
//! - pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK)
//! - pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pos04C;

// Unsafe mutex types that should be avoided
const UNSAFE_MUTEX_TYPES: &[&str] = &["PTHREAD_MUTEX_NORMAL", "PTHREAD_MUTEX_DEFAULT"];

impl CertRule for Pos04C {
    fn rule_id(&self) -> &'static str {
        "POS04-C"
    }

    fn description(&self) -> &'static str {
        "Avoid using PTHREAD_MUTEX_NORMAL type mutex locks"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "POS04-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        // Look for pthread_mutexattr_settype calls
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_mutex_settype(&call, source, &mut violations);
        }
        violations
    }
}

impl Pos04C {
    fn check_mutex_settype(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(func) = node.child_by_field_name("function") {
            let func_name = get_node_text(&func, source);
            if func_name == "pthread_mutexattr_settype" {
                // Get the second argument (mutex type)
                if let Some(args) = node.child_by_field_name("arguments") {
                    let mut arg_idx = 0;
                    for j in 0..args.child_count() {
                        if let Some(arg) = args.child(j) {
                            let arg_kind = arg.kind();
                            if arg_kind != "(" && arg_kind != ")" && arg_kind != "," {
                                arg_idx += 1;
                                if arg_idx == 2 {
                                    // This is the mutex type argument
                                    let type_text = get_node_text(&arg, source);
                                    if UNSAFE_MUTEX_TYPES.contains(&type_text) {
                                        let pos = node.start_position();
                                        violations.push(RuleViolation {
                                            rule_id: self.rule_id().to_string(),
                                            severity: Severity::Low,
                                            message: format!(
                                                "Use of {} mutex type has undefined behavior; use PTHREAD_MUTEX_ERRORCHECK or PTHREAD_MUTEX_RECURSIVE instead",
                                                type_text
                                            ),
                                            file_path: String::new(),
                                            line: pos.row + 1,
                                            column: pos.column + 1,
                                            suggestion: Some(
                                                "Replace with PTHREAD_MUTEX_ERRORCHECK or PTHREAD_MUTEX_RECURSIVE".to_string()
                                            ),
                                            ..Default::default()
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
