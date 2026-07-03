//! CON32-C: Prevent data races when accessing bit-fields from multiple threads
//!
//! When accessing a bit-field, a thread may inadvertently access a separate bit-field
//! in adjacent memory. This is because compilers are required to store multiple adjacent
//! bit-fields in one storage unit whenever they fit. Consequently, data races may exist
//! not just on a bit-field accessed by multiple threads but also on other bit-fields
//! sharing the same byte or word.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! struct multi_threaded_flags {
//!   unsigned int flag1 : 2;
//!   unsigned int flag2 : 2;
//! };
//!
//! struct multi_threaded_flags flags;
//!
//! int thread1(void *arg) {
//!   flags.flag1 = 1;  // Data race: may access same memory as flag2
//!   return 0;
//! }
//!
//! int thread2(void *arg) {
//!   flags.flag2 = 2;  // Data race: may access same memory as flag1
//!   return 0;
//! }
//! ```
//!
//! **Compliant (Mutex):**
//! ```c
//! #include <threads.h>
//!
//! struct multi_threaded_flags {
//!   unsigned int flag1 : 2;
//!   unsigned int flag2 : 2;
//! };
//!
//! struct mtf_mutex {
//!   struct multi_threaded_flags s;
//!   mtx_t mutex;
//! };
//!
//! int thread1(void *arg) {
//!   mtx_lock(&flags.mutex);
//!   flags.s.flag1 = 1;
//!   mtx_unlock(&flags.mutex);
//!   return 0;
//! }
//! ```
//!
//! **Compliant (Separate bytes):**
//! ```c
//! struct multi_threaded_flags {
//!   unsigned char flag1;  // No bit-fields
//!   unsigned char flag2;
//! };
//! ```
//!
//! ## Detection Strategy:
//! - Find struct definitions containing bit-fields
//! - Track accesses to bit-field members
//! - Check if bit-field accesses are in functions that look like thread functions
//! - Check if bit-field accesses are protected by mutex locks
//! - Flag unprotected bit-field accesses in potential thread functions

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Con32C;

impl CertRule for Con32C {
    fn rule_id(&self) -> &'static str {
        "CON32-C"
    }

    fn description(&self) -> &'static str {
        "Prevent data races when accessing bit-fields from multiple threads"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "CON32-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: collect structs that contain bit-fields
        let bitfield_structs = self.collect_bitfield_structs(node, source);

        // Second pass: find accesses to bit-field members without mutex protection
        self.check_node(node, source, &bitfield_structs, &mut violations);

        violations
    }
}

impl Con32C {
    /// Collect struct names that contain bit-fields and their bit-field member names
    fn collect_bitfield_structs(
        &self,
        node: &Node,
        source: &str,
    ) -> HashMap<String, HashSet<String>> {
        let mut bitfield_structs = HashMap::new();
        self.find_bitfield_structs(node, source, &mut bitfield_structs);
        bitfield_structs
    }

    fn find_bitfield_structs(
        &self,
        node: &Node,
        source: &str,
        bitfield_structs: &mut HashMap<String, HashSet<String>>,
    ) {
        for struct_node in query::find_descendants_of_kind(*node, "struct_specifier") {
            if let Some(name_node) = struct_node.child_by_field_name("name") {
                let struct_name = get_node_text(&name_node, source).to_string();

                // Check if this struct has bit-fields
                if let Some(body) = struct_node.child_by_field_name("body") {
                    let bitfield_members = self.find_bitfield_members(&body, source);
                    if !bitfield_members.is_empty() {
                        bitfield_structs.insert(struct_name, bitfield_members);
                    }
                }
            }
        }
    }

    fn find_bitfield_members(&self, body: &Node, source: &str) -> HashSet<String> {
        let mut members = HashSet::new();

        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() == "field_declaration" {
                    // Check if this field has a bit-field width
                    if self.is_bitfield_declaration(&child, source) {
                        // Extract the field name
                        if let Some(name) = self.get_field_name(&child, source) {
                            members.insert(name);
                        }
                    }
                }
            }
        }

        members
    }

    fn is_bitfield_declaration(&self, node: &Node, _source: &str) -> bool {
        // A bit-field declaration has a bitfield_clause child (e.g., ": 2")
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "bitfield_clause" {
                    return true;
                }
            }
        }
        false
    }

    fn get_field_name(&self, node: &Node, source: &str) -> Option<String> {
        // Look for field_identifier, field_declarator or identifier in the declaration
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "field_identifier" => {
                        return Some(get_node_text(&child, source).to_string());
                    }
                    "field_declarator" => {
                        if let Some(name) = self.get_identifier_name(&child, source) {
                            return Some(name);
                        }
                    }
                    "identifier" => {
                        return Some(get_node_text(&child, source).to_string());
                    }
                    _ => {}
                }
            }
        }
        None
    }

    fn get_identifier_name(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = self.get_identifier_name(&child, source) {
                    return Some(name);
                }
            }
        }

        None
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        bitfield_structs: &HashMap<String, HashSet<String>>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for function definitions that might be thread functions
        for func_node in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function_for_bitfield_access(
                &func_node,
                source,
                bitfield_structs,
                violations,
            );
        }
    }

    fn check_function_for_bitfield_access(
        &self,
        function_node: &Node,
        source: &str,
        bitfield_structs: &HashMap<String, HashSet<String>>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let func_name = self
            .get_function_name(function_node, source)
            .unwrap_or_else(|| "<unknown>".to_string());

        // Check if this looks like a thread function (has void* parameter or named "thread*")
        if !self.is_potential_thread_function(function_node, source, &func_name) {
            return;
        }

        // Get function body
        let body = match function_node.child_by_field_name("body") {
            Some(b) => b,
            None => return,
        };

        // Check if function uses mutex locks
        let has_mutex = self.uses_mutex_lock(&body, source);

        // Find bit-field accesses in the function
        let bitfield_accesses = self.find_bitfield_accesses(&body, source, bitfield_structs);

        // If function accesses bit-fields without mutex protection, flag it
        if !bitfield_accesses.is_empty() && !has_mutex {
            for (struct_name, member_name, line) in bitfield_accesses {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "Function '{}' accesses bit-field '{}.{}' without mutex protection in a multi-threaded context",
                        func_name, struct_name, member_name
                    ),
                    file_path: String::new(),
                    line,
                    column: 0,
                    suggestion: Some(
                        "Protect bit-field accesses with mutex locks or use separate byte-sized members instead of bit-fields".to_string()
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn get_function_name(&self, function_node: &Node, source: &str) -> Option<String> {
        for i in 0..function_node.child_count() {
            if let Some(child) = function_node.child(i) {
                if child.kind() == "function_declarator" {
                    if let Some(name) = self.get_identifier_name(&child, source) {
                        return Some(name);
                    }
                }
            }
        }
        None
    }

    fn is_potential_thread_function(
        &self,
        function_node: &Node,
        source: &str,
        func_name: &str,
    ) -> bool {
        // Check if function name suggests it's a thread function
        if func_name.to_lowercase().contains("thread") {
            return true;
        }

        // Check if function has void* parameter (common for thread functions)
        for i in 0..function_node.child_count() {
            if let Some(child) = function_node.child(i) {
                if child.kind() == "function_declarator" {
                    if let Some(params) = child.child_by_field_name("parameters") {
                        for j in 0..params.child_count() {
                            if let Some(param) = params.child(j) {
                                if param.kind() == "parameter_declaration" {
                                    let param_text = get_node_text(&param, source);
                                    if param_text.contains("void") && param_text.contains("*") {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        false
    }

    fn uses_mutex_lock(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(func) = n.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&func, source);
            matches!(
                func_name,
                "mtx_lock" | "mtx_unlock" | "pthread_mutex_lock" | "pthread_mutex_unlock"
            )
        })
        .is_some()
    }

    fn find_bitfield_accesses(
        &self,
        node: &Node,
        source: &str,
        bitfield_structs: &HashMap<String, HashSet<String>>,
    ) -> Vec<(String, String, usize)> {
        let mut accesses = Vec::new();
        self.collect_bitfield_accesses(node, source, bitfield_structs, &mut accesses);
        accesses
    }

    fn collect_bitfield_accesses(
        &self,
        node: &Node,
        source: &str,
        bitfield_structs: &HashMap<String, HashSet<String>>,
        accesses: &mut Vec<(String, String, usize)>,
    ) {
        // Look for field_expression (e.g., flags.flag1)
        for field_expr in query::find_descendants_of_kind(*node, "field_expression") {
            if let Some(field_node) = field_expr.child_by_field_name("field") {
                let field_name = get_node_text(&field_node, source).to_string();

                // Try to determine the struct type
                if let Some(object) = field_expr.child_by_field_name("argument") {
                    let object_text = get_node_text(&object, source);

                    // Check if this field belongs to a bit-field struct
                    for (struct_name, members) in bitfield_structs {
                        if members.contains(&field_name) {
                            // Found a bit-field access
                            let line = field_expr.start_position().row + 1;
                            accesses.push((struct_name.clone(), field_name.clone(), line));
                            break;
                        }
                    }

                    // Also check for nested access like flags.s.flag1
                    if object_text.contains('.') {
                        // This is a nested field access
                        for (struct_name, members) in bitfield_structs {
                            if members.contains(&field_name) {
                                let line = field_expr.start_position().row + 1;
                                accesses.push((struct_name.clone(), field_name.clone(), line));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}
