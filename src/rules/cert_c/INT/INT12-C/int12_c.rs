// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! INT12-C: Do not make assumptions about the type of a plain int bit-field when used in an expression
//!
//! Plain `int` bit-fields have implementation-defined signedness, creating portability issues.
//! Always use explicit `signed int` or `unsigned int` for bit-fields.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! struct {
//!     int a: 8;  // Plain int - implementation-defined signedness
//! } bits = {255};
//! ```
//!
//! **Compliant:**
//! ```c
//! struct {
//!     unsigned int a: 8;  // Explicit signedness
//! } bits = {255};
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{get_node_text, typedef_definition_in_scope};
use crate::utility::cert_c::declarator_utils::typedef_declarators;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Int12C;

impl CertRule for Int12C {
    fn rule_id(&self) -> &'static str {
        "INT12-C"
    }

    fn description(&self) -> &'static str {
        "Do not make assumptions about the type of a plain int bit-field when used in an expression"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "INT12-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Recursively traverse the tree
        self.traverse(node, source, &mut violations);

        violations
    }
}

impl Int12C {
    /// Traverse the AST looking for bit-field declarations
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for field in query::find_descendants_of_kind(*node, "field_declaration") {
            self.check_field_declaration(&field, source, violations);
        }
    }

    /// Report a field declaration whose own bit-fields have the type plain
    /// `int`: the `int` specifier alone, or a typedef in scope that names it
    /// (C11 6.7.2p5 and its footnote: either way the signedness is
    /// implementation-defined). Only the declaration's own declarators are
    /// read, so a member that is a structure, union or enumeration with
    /// bit-fields inside it is not reported for them; those are reported as
    /// their own field declarations. An unnamed bit-field (`int : 3;`) names
    /// nothing an expression can read and is not reported.
    fn check_field_declaration(
        &self,
        field: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(ty) = field.child_by_field_name("type") else {
            return;
        };
        if !designates_plain_int(&ty, source, 8) {
            return;
        }
        // The first named bit-field: a declarator followed by its width
        let mut cursor = field.walk();
        let children: Vec<Node> = field.named_children(&mut cursor).collect();
        let Some(name) = children.windows(2).find_map(|pair| {
            (pair[1].kind() == "bitfield_clause"
                && pair[0].kind() == "field_identifier"
                // `int : 3;` parses with a missing, empty identifier
                && !pair[0].is_missing()
                && pair[0].start_byte() < pair[0].end_byte())
            .then(|| get_node_text(&pair[0], source).to_string())
        }) else {
            return;
        };
        let (line, column) = (
            field.start_position().row + 1,
            field.start_position().column + 1,
        );

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            message: format!(
                "Bit-field '{}' uses plain 'int' with implementation-defined signedness. \
                 Use explicit 'signed int' or 'unsigned int' instead.",
                name
            ),
            severity: self.severity(),
            line,
            column,
            file_path: String::new(),
            suggestion: Some(format!(
                "Change 'int {}' to 'signed int {}' or 'unsigned int {}'",
                name, name, name
            )),
            requires_manual_review: None,
        });
    }
}

/// Whether the type specifier `ty` is plain `int`: the `int` keyword alone
/// (`signed int` and `unsigned int` are sized specifiers), or a typedef name
/// in scope whose own definition is a plain `int` with no derivation, through
/// up to `depth` typedefs.
fn designates_plain_int(ty: &Node, source: &str, depth: usize) -> bool {
    match ty.kind() {
        "primitive_type" => get_node_text(ty, source) == "int",
        "type_identifier" if depth > 0 => {
            let name = get_node_text(ty, source);
            let Some(typedef) = typedef_definition_in_scope(ty, name, source) else {
                return false;
            };
            typedef_declarators(&typedef)
                .iter()
                .any(|d| d.kind() == "type_identifier" && get_node_text(d, source) == name)
                && typedef
                    .child_by_field_name("type")
                    .is_some_and(|t| designates_plain_int(&t, source, depth - 1))
        }
        _ => false,
    }
}
