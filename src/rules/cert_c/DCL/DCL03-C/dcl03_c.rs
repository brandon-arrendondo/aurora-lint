// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use std::cell::RefCell;

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils;
use crate::utility::cert_c::constant_expression::{ConstantExpressions, Constness, ProjectTables};
use lang_parsing_substrate::query;
use tree_sitter::Node;

#[derive(Default)]
pub struct Dcl03C {
    /// The project's macro and typedef tables, for a constant a header
    /// defines.
    project: RefCell<ProjectTables>,
}

impl CertRule for Dcl03C {
    fn rule_id(&self) -> &'static str {
        "DCL03-C"
    }

    fn description(&self) -> &'static str {
        "Use a static assertion to test the value of a constant expression"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "DCL03-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = ProjectTables::from_context(context);
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let project = self.project.borrow();
        let constants = ConstantExpressions::new(*node, source, &project);
        query::find_descendants_of_kind(*node, "call_expression")
            .into_iter()
            .filter_map(|call| self.check_call_expression(call, source, &constants))
            .collect()
    }
}

impl Dcl03C {
    fn check_call_expression<'a>(
        &self,
        node: Node<'a>,
        source: &str,
        constants: &ConstantExpressions<'a, '_>,
    ) -> Option<RuleViolation> {
        let function = node.child_by_field_name("function")?;
        let func_text = ast_utils::get_node_text(&function, source);

        // Check if this is an assert() call
        if func_text != "assert" {
            return None;
        }

        // An assertion a static assertion could make: its condition is an
        // integer constant expression (C11 6.6, 6.7.10), whatever its names
        // are spelled like. One that reads a name nothing in reach defines
        // is not shown to be.
        let arguments = node.child_by_field_name("arguments")?;
        let mut cursor = arguments.walk();
        let condition = arguments
            .named_children(&mut cursor)
            .find(|n| n.kind() != "comment")?;
        if constants.integer_constant_expression(&condition) != Constness::Constant {
            return None;
        }

        let start_point = node.start_position();
        Some(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::Low,
            message: "Runtime assert() used with constant expression; consider using static_assert() instead".to_string(),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(
                "Replace assert() with static_assert() to evaluate at compile time"
                    .to_string(),
            ),
            ..Default::default()
        })
    }
}
