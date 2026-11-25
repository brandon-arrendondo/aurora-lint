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
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{get_node_text, typedef_definition_in_scope};
use crate::utility::cert_c::declarator_utils::{typedef_declarators, TypedefShape};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use tree_sitter::Node;

/// The project's typedef definitions, for a typedef name this file uses
/// but does not define (one from a header).
#[derive(Default)]
pub struct Int12C {
    typedef_arms: RefCell<Arc<HashMap<String, Vec<String>>>>,
}

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

    fn set_project_context(&self, context: &ProjectContext) {
        *self.typedef_arms.borrow_mut() = context.typedef_arms.clone();
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
        if !self.designates_plain_int(&ty, source, 8) {
            return;
        }
        // Every named bit-field: a declarator followed by its width
        let mut cursor = field.walk();
        let children: Vec<Node> = field.named_children(&mut cursor).collect();
        let names: Vec<String> = children
            .windows(2)
            .filter(|pair| {
                pair[1].kind() == "bitfield_clause"
                    && pair[0].kind() == "field_identifier"
                    // `int : 3;` parses with a missing, empty identifier
                    && !pair[0].is_missing()
                    && pair[0].start_byte() < pair[0].end_byte()
            })
            .map(|pair| get_node_text(&pair[0], source).to_string())
            .collect();
        if names.is_empty() {
            return;
        }
        let quoted: Vec<String> = names.iter().map(|n| format!("'{n}'")).collect();
        let (subject, verb) = if names.len() == 1 {
            ("Bit-field", "uses")
        } else {
            ("Bit-fields", "use")
        };
        let spelled = get_node_text(&ty, source);
        let suggestion = if ty.kind() == "primitive_type" {
            format!(
                "Declare {} as 'signed int' or 'unsigned int' instead of 'int'",
                quoted.join(", ")
            )
        } else {
            format!(
                "'{spelled}' is a typedef of plain 'int'; declare {} with a type that is \
                 explicitly 'signed int' or 'unsigned int'",
                quoted.join(", ")
            )
        };

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            message: format!(
                "{subject} {} {verb} plain 'int' with implementation-defined signedness. \
                 Use explicit 'signed int' or 'unsigned int' instead.",
                quoted.join(", ")
            ),
            severity: self.severity(),
            line: field.start_position().row + 1,
            column: field.start_position().column + 1,
            file_path: String::new(),
            suggestion: Some(suggestion),
            requires_manual_review: None,
        });
    }

    /// Whether the type specifier `ty` is plain `int`: the `int` keyword
    /// alone (`signed int` and `unsigned int` are sized specifiers), or a
    /// typedef name whose definition is a plain `int` with no derivation,
    /// through up to `depth` typedefs. The typedef in scope in this file
    /// answers; a name this file never defines as a typedef is read from
    /// the project's definitions of it, all of which must be plain `int`.
    fn designates_plain_int(&self, ty: &Node, source: &str, depth: usize) -> bool {
        match ty.kind() {
            "primitive_type" => get_node_text(ty, source) == "int",
            "type_identifier" if depth > 0 => {
                let name = get_node_text(ty, source);
                if let Some(typedef) = typedef_definition_in_scope(ty, name, source) {
                    return typedef_declarators(&typedef).iter().any(|d| {
                        d.kind() == "type_identifier" && get_node_text(d, source) == name
                    }) && typedef
                        .child_by_field_name("type")
                        .is_some_and(|t| self.designates_plain_int(&t, source, depth - 1));
                }
                !file_defines_typedef(ty, name, source)
                    && self.project_typedef_is_plain_int(name, depth)
            }
            _ => false,
        }
    }

    /// Whether every project definition of the typedef `name` is a plain
    /// `int`, directly or through other typedefs, up to `depth` of them.
    fn project_typedef_is_plain_int(&self, name: &str, depth: usize) -> bool {
        let arms = self.typedef_arms.borrow();
        let Some(texts) = arms.get(name).filter(|t| !t.is_empty()) else {
            return false;
        };
        texts.iter().all(|text| {
            let text = text.trim();
            text == "int"
                || (depth > 1
                    && text != name
                    && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && !text.is_empty()
                    && self.project_typedef_is_plain_int(text, depth - 1))
        })
    }
}

/// Whether the file holding `node` declares `name` as a typedef anywhere.
fn file_defines_typedef(node: &Node, name: &str, source: &str) -> bool {
    let mut root = *node;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    query::find_descendants_of_kind(root, "type_definition")
        .iter()
        .any(|typedef| {
            typedef_declarators(typedef)
                .iter()
                .any(|d| TypedefShape::of(d, source).name.as_deref() == Some(name))
        })
}
