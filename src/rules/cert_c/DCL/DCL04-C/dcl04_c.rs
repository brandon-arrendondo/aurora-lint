//! DCL04-C: Do not declare more than one variable per declaration
//!
//! This rule detects when multiple variables are declared in a single declaration statement.
//! Multiple declarations can cause confusion about variable types and initialization.
//!
//! VIOLATIONS:
//! - char *src = 0, c = 0;         // src is char*, c is char - type confusion
//! - int i, j = 1;                 // Only j is initialized
//! - int *p, q, r;                 // p is int*, but q and r are int
//!
//! COMPLIANT:
//! - char *src = 0;  /* Source */
//!   char c = 0;     /* Character */
//! - int i = 1;
//!   int j = 1;
//!
//! EXCEPTIONS:
//! - for (int i = 0, j = 0; ...) {} // Multiple loop control variables OK

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Dcl04C;

impl CertRule for Dcl04C {
    fn rule_id(&self) -> &'static str {
        "DCL04-C"
    }

    fn description(&self) -> &'static str {
        "Do not declare more than one variable per declaration"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL04-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        query::find_descendants_of_kind(*node, "declaration")
            .into_iter()
            .filter_map(|declaration| self.check_declaration(declaration, source))
            .collect()
    }
}

impl Dcl04C {
    fn check_declaration(&self, node: Node, source: &str) -> Option<RuleViolation> {
        // Skip if this is a for loop declaration (exception)
        if self.is_for_loop_declaration(&node) {
            return None;
        }

        // DCL04-C-EX2: "Multiple, simple variable declarations can be
        // declared on the same line given that there are no
        // initializations" — e.g. `int i, j, k;`. Only plain (non-pointer,
        // non-array), uninitialized declarators qualify; a mix like
        // `int *p, q, r;` or `int i, j = 1;` still has the type/init
        // ambiguity this rule targets.
        if self.is_uninitialized_simple_multi_declaration(&node) {
            return None;
        }

        let declarator_count = self.count_declarators(&node);

        if declarator_count > 1 {
            let start_point = node.start_position();
            let declaration_text = ast_utils::get_node_text(&node, source);

            return Some(RuleViolation {
                rule_id: "DCL04-C".to_string(),
                severity: Severity::Low,
                message: format!(
                    "Multiple variables ({}) declared in single declaration: {}",
                    declarator_count,
                    declaration_text.lines().next().unwrap_or(&declaration_text)
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(
                    "Declare each variable on its own line with an explanatory comment".to_string(),
                ),
                ..Default::default()
            });
        }

        None
    }
    /// DCL04-C-EX2: true if every direct declarator child is a plain,
    /// uninitialized `identifier` (no init_declarator, pointer_declarator,
    /// or array_declarator among them) and there is more than one.
    fn is_uninitialized_simple_multi_declaration(&self, declaration_node: &Node) -> bool {
        let mut identifier_count = 0;
        for i in 0..declaration_node.child_count() {
            let Some(child) = declaration_node.child(i) else {
                continue;
            };
            match child.kind() {
                "identifier" if self.is_direct_declarator(&child, declaration_node) => {
                    identifier_count += 1;
                }
                "init_declarator"
                | "pointer_declarator"
                | "array_declarator"
                | "function_declarator" => {
                    // Any non-plain or initialized declarator disqualifies
                    // the whole declaration from EX2.
                    return false;
                }
                _ => {}
            }
        }
        identifier_count > 1
    }

    /// Check if this declaration is part of a for loop (exception to the rule)
    fn is_for_loop_declaration(&self, node: &Node) -> bool {
        if let Some(parent) = node.parent() {
            // Check if parent is a for_statement
            if parent.kind() == "for_statement" {
                return true;
            }
        }
        false
    }

    /// Count the number of declarators in a declaration
    fn count_declarators(&self, declaration_node: &Node) -> usize {
        let mut count = 0;

        for i in 0..declaration_node.child_count() {
            if let Some(child) = declaration_node.child(i) {
                match child.kind() {
                    // init_declarator has format: declarator = initializer
                    "init_declarator" => {
                        count += 1;
                    }
                    // Plain declarator without initialization
                    "pointer_declarator"
                    | "array_declarator"
                    | "function_declarator"
                    | "identifier"
                        // Check if this is a direct declarator (not part of init_declarator)
                        if self.is_direct_declarator(&child, declaration_node) => {
                            count += 1;
                        }
                    _ => {}
                }
            }
        }

        count
    }

    /// Check if a node is a direct declarator child (not nested in init_declarator)
    fn is_direct_declarator(&self, node: &Node, declaration: &Node) -> bool {
        // A declarator is direct if its parent is the declaration itself
        if let Some(parent) = node.parent() {
            if parent.id() == declaration.id() {
                // Make sure it's actually a declarator kind
                matches!(
                    node.kind(),
                    "pointer_declarator"
                        | "array_declarator"
                        | "function_declarator"
                        | "identifier"
                )
            } else {
                false
            }
        } else {
            false
        }
    }
}
