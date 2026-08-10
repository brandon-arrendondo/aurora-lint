//! DCL39-C: Avoid information leakage when passing a structure across a trust boundary
//!
//! Structures may contain padding bytes with uninitialized data. When passing
//! structures across trust boundaries (kernel/user space), these padding bytes
//! can leak sensitive information.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! struct test { int a; char b; int c; };
//! struct test arg = {.a = 1, .b = 2, .c = 3};
//! copy_to_user(usr_buf, &arg, sizeof(arg));  // Padding leaks data
//! ```
//!
//! **Compliant:**
//! ```c
//! // Use memset to zero all bytes including padding
//! memset(&arg, 0, sizeof(arg));
//! arg.a = 1; arg.b = 2; arg.c = 3;
//! copy_to_user(usr_buf, &arg, sizeof(arg));
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Dcl39C;

/// Tracks structure variable information
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct StructVarInfo {
    var_name: String,
    #[allow(dead_code)]
    struct_type: String,
    is_zeroed: bool,
}

impl CertRule for Dcl39C {
    fn rule_id(&self) -> &'static str {
        "DCL39-C"
    }

    fn description(&self) -> &'static str {
        "Avoid information leakage when passing a structure across a trust boundary"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "DCL39-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        let mut safe_struct_types: HashSet<String> = HashSet::new();

        // Find packed structs and structs with explicit padding
        // NOTE: memset() is NOT sufficient per CERT wiki - subsequent field
        // assignments can leak data through padding bits
        self.find_safe_struct_types(node, source, &mut safe_struct_types);

        // File-scope struct variable declarations (direct children of the
        // translation unit) are genuinely shared across every function, so
        // it's correct to seed every function's scope with them.
        let mut global_struct_vars: HashMap<String, StructVarInfo> = HashMap::new();
        self.collect_top_level_struct_vars(node, source, &mut global_struct_vars);

        // Each function gets its own scope: a local struct variable declared
        // inside one function is a *different* object than a same-named
        // local (or parameter) declared inside another function. Without
        // this, struct_vars keyed only on variable name would let a
        // struct declared in one function "leak" its type into an
        // unrelated same-named variable (even a non-struct one) checked in
        // a completely different function. Mirrors EXP39-C's per-function
        // reset pattern.
        let functions = query::find_descendants_of_kind(*node, "function_definition");

        if functions.is_empty() {
            // No functions at all - fall back to treating the whole
            // translation unit as a single scope, matching pre-fix behavior
            // for this edge case.
            let mut struct_vars = global_struct_vars.clone();
            self.analyze_structures(
                node,
                source,
                &mut struct_vars,
                &safe_struct_types,
                &mut violations,
            );
        } else {
            for func in functions {
                let mut struct_vars = global_struct_vars.clone();
                self.analyze_structures(
                    &func,
                    source,
                    &mut struct_vars,
                    &safe_struct_types,
                    &mut violations,
                );
            }
        }

        violations
    }
}

impl Dcl39C {
    /// Find safe struct types (packed, explicit padding, etc.)
    fn find_safe_struct_types(&self, node: &Node, source: &str, safe_types: &mut HashSet<String>) {
        for node in query::find_descendants_of_kind(*node, "struct_specifier") {
            let node = &node;
            let struct_text = get_node_text(node, source);
            let struct_name = self.extract_struct_name(node, source);

            // Check for __attribute__((__packed__))
            if struct_text.contains("__attribute__") && struct_text.contains("packed") {
                if !struct_name.is_empty() {
                    safe_types.insert(format!("struct {}", struct_name));
                }
            }

            // Check for explicit padding fields
            if self.has_explicit_padding_fields(node, source) {
                if !struct_name.is_empty() {
                    safe_types.insert(format!("struct {}", struct_name));
                }
            }

            // Check for bitfield padding
            if self.has_bitfield_padding(node, source) {
                if !struct_name.is_empty() {
                    safe_types.insert(format!("struct {}", struct_name));
                }
            }

            // Check if struct is inside a #pragma pack context
            if self.is_inside_pragma_pack(node, source) {
                if !struct_name.is_empty() {
                    safe_types.insert(format!("struct {}", struct_name));
                }
            }
        }
    }

    /// Check if a node is inside a #pragma pack(push, 1) ... #pragma pack(pop) region
    fn is_inside_pragma_pack(&self, node: &Node, source: &str) -> bool {
        let struct_line = node.start_position().row;

        // Look for #pragma pack directives in the source before this struct
        let source_lines: Vec<&str> = source.lines().collect();

        // Search backwards for #pragma pack(push, 1)
        let mut found_push = false;
        for line_idx in (0..struct_line).rev() {
            if line_idx >= source_lines.len() {
                continue;
            }
            let line = source_lines[line_idx];
            if line.contains("#pragma") && line.contains("pack") {
                if line.contains("push") && line.contains("1") {
                    found_push = true;
                    break;
                } else if line.contains("pop") {
                    // Found a pop before a push, not in packed region
                    return false;
                }
            }
        }

        // If we found push, check if there's a pop after the struct
        if found_push {
            for line in source_lines.iter().skip(struct_line + 1) {
                if line.contains("#pragma") && line.contains("pack") && line.contains("pop") {
                    return true;
                }
            }
        }

        false
    }

    /// Extract struct name from struct_specifier
    fn extract_struct_name(&self, struct_node: &Node, source: &str) -> String {
        for i in 0..struct_node.child_count() {
            if let Some(child) = struct_node.child(i) {
                if child.kind() == "type_identifier" {
                    return get_node_text(&child, source).to_string();
                }
            }
        }
        String::new()
    }

    /// Check if struct has explicit padding fields
    fn has_explicit_padding_fields(&self, struct_node: &Node, source: &str) -> bool {
        for i in 0..struct_node.child_count() {
            if let Some(child) = struct_node.child(i) {
                if child.kind() == "field_declaration_list" {
                    for j in 0..child.child_count() {
                        if let Some(field) = child.child(j) {
                            let field_text = get_node_text(&field, source).to_lowercase();
                            if field_text.contains("padding") {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if struct has bitfield padding
    fn has_bitfield_padding(&self, struct_node: &Node, source: &str) -> bool {
        for i in 0..struct_node.child_count() {
            if let Some(child) = struct_node.child(i) {
                if child.kind() == "field_declaration_list" {
                    for j in 0..child.child_count() {
                        if let Some(field) = child.child(j) {
                            if field.kind() == "field_declaration" {
                                let field_text = get_node_text(&field, source).to_lowercase();
                                // Check for bitfield with padding in name
                                if field_text.contains(":") && field_text.contains("padding") {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Collect struct variable declarations that are direct children of the
    /// translation unit (i.e. file scope, not inside any function body).
    /// These are shared across every function, unlike function-local
    /// declarations which must stay scoped per-function (see `check`).
    fn collect_top_level_struct_vars(
        &self,
        node: &Node,
        source: &str,
        struct_vars: &mut HashMap<String, StructVarInfo>,
    ) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "declaration" {
                    if let Some((var_name, struct_type)) =
                        self.extract_struct_declaration(&child, source)
                    {
                        struct_vars.insert(
                            var_name.clone(),
                            StructVarInfo {
                                var_name,
                                struct_type,
                                is_zeroed: false,
                            },
                        );
                    }
                }
            }
        }
    }

    /// Analyze structures for trust boundary violations
    fn analyze_structures(
        &self,
        node: &Node,
        source: &str,
        struct_vars: &mut HashMap<String, StructVarInfo>,
        safe_struct_types: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for node in query::find_descendants_of_kinds(*node, &["declaration", "call_expression"]) {
            // Check for structure variable declarations
            if node.kind() == "declaration" {
                if let Some((var_name, struct_type)) =
                    self.extract_struct_declaration(&node, source)
                {
                    struct_vars.insert(
                        var_name.clone(),
                        StructVarInfo {
                            var_name,
                            struct_type,
                            is_zeroed: false, // Not used anymore - memset is insufficient
                        },
                    );
                }
            }

            // Check for trust boundary function calls
            if node.kind() == "call_expression" {
                if let Some(function) = node.child_by_field_name("function") {
                    let func_name = get_node_text(&function, source);

                    if self.is_trust_boundary_function(&func_name) {
                        // Check if a structure is passed directly
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let arg_list = self.get_arguments(&args, source);
                            for arg in &arg_list {
                                // Check for &struct_var pattern
                                if let Some(stripped) = arg.strip_prefix('&') {
                                    let var_name = stripped.trim().to_string();
                                    // Check if this is a known struct variable that wasn't zeroed
                                    if let Some(info) = struct_vars.get(&var_name) {
                                        // Skip if struct type is safe (packed, explicit padding, etc.)
                                        if safe_struct_types.contains(&info.struct_type) {
                                            continue;
                                        }

                                        // Structure passed to trust boundary - this is a violation
                                        // Note: memset() is NOT sufficient per CERT wiki
                                        violations.push(RuleViolation {
                                            rule_id: self.rule_id().to_string(),
                                            message: format!(
                                                "Structure '{}' passed to trust boundary function '{}' \
                                                 may leak padding bytes. Use packed attributes, explicit \
                                                 padding fields, or serialize fields individually.",
                                                var_name, func_name
                                            ),
                                            severity: self.severity(),
                                            line: node.start_position().row + 1,
                                            column: node.start_position().column + 1,
                                            file_path: String::new(),
                                            suggestion: Some(format!(
                                                "Use __attribute__((__packed__)) or serialize fields: \
                                                 copy_to_user(buf, &{}.a, sizeof({}.a)); ...",
                                                var_name, var_name
                                            )),
                                            requires_manual_review: None,
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

    /// Extract structure variable name and type from declaration
    fn extract_struct_declaration(&self, decl: &Node, source: &str) -> Option<(String, String)> {
        let decl_text = get_node_text(decl, source);

        // Check if this is a struct declaration
        if !decl_text.contains("struct ") {
            return None;
        }

        // Look for type specifier and declarator
        let mut struct_type = String::new();
        let mut var_name = String::new();

        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "struct_specifier" || child.kind() == "type_identifier" {
                    struct_type = get_node_text(&child, source).to_string();
                }
                if child.kind() == "init_declarator" || child.kind() == "identifier" {
                    var_name = self.extract_var_name(&child, source);
                }
            }
        }

        if !var_name.is_empty() && !struct_type.is_empty() {
            Some((var_name, struct_type))
        } else {
            None
        }
    }

    /// Extract variable name from declarator
    fn extract_var_name(&self, node: &Node, source: &str) -> String {
        if node.kind() == "identifier" {
            return get_node_text(node, source).to_string();
        }

        // Recurse to find identifier
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let name = self.extract_var_name(&child, source);
                if !name.is_empty() {
                    return name;
                }
            }
        }

        String::new()
    }

    /// Check if function is a trust boundary function
    fn is_trust_boundary_function(&self, name: &str) -> bool {
        matches!(
            name,
            "copy_to_user"
                | "write"
                | "send"
                | "sendto"
                | "sendmsg"
                | "ioctl"
                | "fwrite"
                | "writev"
        )
    }

    /// Get argument strings from argument_list node
    fn get_arguments(&self, args_node: &Node, source: &str) -> Vec<String> {
        let mut arguments = Vec::new();

        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                let kind = child.kind();
                if kind != "," && kind != "(" && kind != ")" {
                    let arg_text = get_node_text(&child, source).to_string();
                    arguments.push(arg_text);
                }
            }
        }

        arguments
    }
}
