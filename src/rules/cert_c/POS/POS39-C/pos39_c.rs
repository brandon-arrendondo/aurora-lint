//! POS39-C: Use the correct byte ordering when transferring data between systems
//!
//! When receiving network data into multi-byte integer types, the byte order
//! must be converted using ntohl(), ntohs(), etc. to handle endianness differences.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! uint32_t num;
//! recv(sock, &num, sizeof(uint32_t), 0);
//! printf("%u\n", num);  // No byte order conversion
//! ```
//!
//! **Compliant:**
//! ```c
//! uint32_t num;
//! recv(sock, &num, sizeof(uint32_t), 0);
//! num = ntohl(num);  // Convert from network byte order
//! printf("%u\n", num);
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Pos39C;

impl CertRule for Pos39C {
    fn rule_id(&self) -> &'static str {
        "POS39-C"
    }

    fn description(&self) -> &'static str {
        "Use the correct byte ordering when transferring data between systems"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "POS39-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Each function gets its own scope for all three tracking maps: a
        // same-named variable in a different function is a different
        // object. `find_multi_byte_vars` doesn't see parameter
        // declarations (only `declaration`-kind locals), so a stale
        // "declared as uint32_t somewhere in this file" entry from one
        // function could leak into an unrelated same-named *plain* `int`
        // variable in another function and misfire the recv-without-
        // conversion check there -- confirmed via a minimal repro where
        // `func_b`'s plain `int id` got reported as "uint32_t" solely
        // because an unrelated `func_a` happened to declare a `uint32_t
        // id` elsewhere in the file (task 418). `converted_vars` has the
        // same cross-function leak in the opposite direction (a
        // conversion in one function could mask a missing conversion on
        // an unrelated same-named variable in another). Scope all three
        // passes per `function_definition`, mirroring EXP39-C/STR32-C's
        // per-function reset pattern.
        let functions = query::find_descendants_of_kind(*node, "function_definition");
        let scopes: Vec<Node> = if functions.is_empty() {
            vec![*node]
        } else {
            functions
        };

        for scope in scopes {
            let mut multi_byte_vars: HashMap<String, String> = HashMap::new();
            let mut converted_vars: HashSet<String> = HashSet::new();
            let mut received_vars: HashMap<String, (usize, usize)> = HashMap::new();

            self.find_multi_byte_vars(&scope, source, &mut multi_byte_vars);
            self.find_byte_order_conversions(&scope, source, &mut converted_vars);
            self.find_recv_calls(
                &scope,
                source,
                &multi_byte_vars,
                &converted_vars,
                &mut received_vars,
                &mut violations,
            );
        }

        violations
    }
}

impl Pos39C {
    /// Find multi-byte integer variable declarations
    fn find_multi_byte_vars(&self, node: &Node, source: &str, vars: &mut HashMap<String, String>) {
        for node in query::find_descendants_of_kind(*node, "declaration") {
            let decl_text = get_node_text(&node, source);

            // Check for multi-byte integer types
            if self.is_multi_byte_type(&decl_text) {
                // Extract variable name
                if let Some(var_name) = self.extract_var_name(&node, source) {
                    let type_name = self.extract_type_name(&decl_text);
                    vars.insert(var_name, type_name);
                }
            }
        }
    }

    /// Check if type is multi-byte integer
    fn is_multi_byte_type(&self, text: &str) -> bool {
        text.contains("uint32_t")
            || text.contains("uint16_t")
            || text.contains("int32_t")
            || text.contains("int16_t")
            || text.contains("uint64_t")
            || text.contains("int64_t")
            || text.contains("unsigned int")
            || text.contains("unsigned short")
    }

    /// Extract type name from declaration
    fn extract_type_name(&self, decl_text: &str) -> String {
        if decl_text.contains("uint32_t") {
            "uint32_t".to_string()
        } else if decl_text.contains("uint16_t") {
            "uint16_t".to_string()
        } else if decl_text.contains("int32_t") {
            "int32_t".to_string()
        } else if decl_text.contains("int16_t") {
            "int16_t".to_string()
        } else {
            "multi-byte".to_string()
        }
    }

    /// Extract variable name from declaration
    fn extract_var_name(&self, decl: &Node, source: &str) -> Option<String> {
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" || child.kind() == "identifier" {
                    return self.find_identifier(&child, source);
                }
            }
        }
        None
    }

    /// Find identifier in node tree
    fn find_identifier(&self, node: &Node, source: &str) -> Option<String> {
        query::find_first_descendant(*node, |n| n.kind() == "identifier")
            .map(|n| get_node_text(&n, source).to_string())
    }

    /// Find byte order conversion function calls
    fn find_byte_order_conversions(
        &self,
        node: &Node,
        source: &str,
        converted: &mut HashSet<String>,
    ) {
        for node in
            query::find_descendants_of_kinds(*node, &["assignment_expression", "call_expression"])
        {
            if node.kind() == "assignment_expression" {
                // Look for: var = ntohl(var)
                if let Some(left) = node.child_by_field_name("left") {
                    let var_name = get_node_text(&left, source);
                    if let Some(right) = node.child_by_field_name("right") {
                        let right_text = get_node_text(&right, source);
                        if self.has_byte_order_conversion(&right_text) {
                            converted.insert(var_name.to_string());
                        }
                    }
                }
            }

            // Also check call expressions for byte order functions
            if node.kind() == "call_expression" {
                if let Some(function) = node.child_by_field_name("function") {
                    let func_name = get_node_text(&function, source);
                    if self.is_byte_order_function(&func_name) {
                        // Mark parent context as having conversion
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let args_text = get_node_text(&args, source);
                            // Extract variable name from arguments
                            let clean_args = args_text.trim_matches(|c| c == '(' || c == ')');
                            converted.insert(clean_args.to_string());
                        }
                    }
                }
            }
        }
    }

    /// Check if text contains byte order conversion
    fn has_byte_order_conversion(&self, text: &str) -> bool {
        text.contains("ntohl")
            || text.contains("ntohs")
            || text.contains("htonl")
            || text.contains("htons")
    }

    /// Check if function is a byte order function
    fn is_byte_order_function(&self, name: &str) -> bool {
        matches!(name, "ntohl" | "ntohs" | "htonl" | "htons")
    }

    /// Find recv calls and check for missing conversions
    fn find_recv_calls(
        &self,
        node: &Node,
        source: &str,
        multi_byte_vars: &HashMap<String, String>,
        converted_vars: &HashSet<String>,
        _received_vars: &mut HashMap<String, (usize, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if func_name == "recv" || func_name == "recvfrom" || func_name == "read" {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let args_text = get_node_text(&args, source);

                        // Check if receiving into a multi-byte variable (look for &var pattern)
                        for (var_name, var_type) in multi_byte_vars {
                            if args_text.contains(&format!("&{}", var_name))
                                || args_text.contains(&format!("(void *)&{}", var_name))
                            {
                                // Check if this variable has byte order conversion
                                if !converted_vars.contains(var_name) {
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        message: format!(
                                            "Network data received into '{}' ({}) without byte order conversion. \
                                             Use ntohl()/ntohs() to convert from network byte order.",
                                            var_name, var_type
                                        ),
                                        severity: self.severity(),
                                        line: node.start_position().row + 1,
                                        column: node.start_position().column + 1,
                                        file_path: String::new(),
                                        suggestion: Some(format!(
                                            "Add: {} = {}({});",
                                            var_name,
                                            if var_type.contains("16") {
                                                "ntohs"
                                            } else {
                                                "ntohl"
                                            },
                                            var_name
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
