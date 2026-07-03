//! DCL12-C: Implement abstract data types using opaque types
//!
//! This rule detects when a struct definition exposes its internal members
//! in a public header, violating information hiding principles.
//!
//! Key violation pattern:
//! - Full struct definition with members PLUS extern function declarations
//!   in the same file (suggests a public header exposing implementation)
//!
//! Compliant patterns:
//! - Forward declaration only (opaque type): `struct X;`
//! - Full struct definition without extern functions (implementation file)
//!
//! Noncompliant pattern:
//!   struct string_mx {
//!     size_t size;
//!     char *cstr;
//!   };
//!   extern errno_t strcpy_m(string_mx *s1, const string_mx *s2);
//!
//! Compliant pattern:
//!   struct string_mx;  // Forward declaration only
//!   extern errno_t strcpy_m(string_mx *s1, const string_mx *s2);

use crate::manifest::{RuleCategory, Severity};
use crate::rules::{CertRule, RuleViolation};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Dcl12C;

impl CertRule for Dcl12C {
    fn rule_id(&self) -> &'static str {
        "DCL12-C"
    }

    fn description(&self) -> &'static str {
        "Implement abstract data types using opaque types"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL12-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Collect all fully-defined structs and extern function declarations
        let mut full_struct_defs: Vec<(String, Node)> = Vec::new();
        let mut has_extern_functions = false;
        let mut structs_used_in_externs: HashSet<String> = HashSet::new();

        self.scan_file(
            node,
            source,
            &mut full_struct_defs,
            &mut has_extern_functions,
            &mut structs_used_in_externs,
        );

        // Only flag if we have BOTH full struct definitions AND extern functions
        if has_extern_functions {
            for (struct_name, struct_node) in &full_struct_defs {
                // Check if this struct is used in extern function declarations
                if structs_used_in_externs.contains(struct_name) {
                    let start_point = struct_node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Low,
                        message: format!(
                            "Struct '{}' exposes implementation details in what appears to be a public interface. \
                            Consider using an opaque type (forward declaration) to hide internal structure.",
                            struct_name
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(format!(
                            "Replace full struct definition with forward declaration: 'struct {};' \
                            Move the full definition to an implementation file.",
                            struct_name
                        )),
                        ..Default::default()
                    });
                }
            }
        }

        violations
    }
}

impl Dcl12C {
    fn scan_file<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        full_struct_defs: &mut Vec<(String, Node<'a>)>,
        has_extern_functions: &mut bool,
        structs_used_in_externs: &mut HashSet<String>,
    ) {
        for n in query::find_descendants_of_kinds(*node, &["struct_specifier", "declaration"]) {
            match n.kind() {
                // Check for struct specifiers with field declarations (full definitions)
                "struct_specifier" => {
                    if let Some(name_node) = n.child_by_field_name("name") {
                        let struct_name = get_node_text(&name_node, source).to_string();
                        // Check if it has a body (field declaration list)
                        if n.child_by_field_name("body").is_some() {
                            full_struct_defs.push((struct_name, n));
                        }
                    }
                }
                // Check for extern function declarations
                "declaration" => {
                    let decl_text = get_node_text(&n, source);
                    if decl_text.starts_with("extern ") && decl_text.contains('(') {
                        *has_extern_functions = true;

                        // Extract struct types used in this declaration
                        self.extract_struct_types_from_decl(&n, source, structs_used_in_externs);
                    }
                }
                _ => {}
            }
        }
    }

    fn extract_struct_types_from_decl(
        &self,
        node: &Node,
        source: &str,
        structs_used: &mut HashSet<String>,
    ) {
        for n in query::find_descendants_of_kinds(*node, &["type_identifier", "struct_specifier"]) {
            match n.kind() {
                // Look for type identifiers that might be struct types
                "type_identifier" => {
                    let type_name = get_node_text(&n, source).to_string();
                    structs_used.insert(type_name);
                }
                // Also check for struct specifiers in parameters
                "struct_specifier" => {
                    if let Some(name_node) = n.child_by_field_name("name") {
                        let struct_name = get_node_text(&name_node, source).to_string();
                        structs_used.insert(struct_name);
                    }
                }
                _ => {}
            }
        }
    }
}
