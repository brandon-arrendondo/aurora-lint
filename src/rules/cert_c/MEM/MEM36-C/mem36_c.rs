use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Mem36C;

impl CertRule for Mem36C {
    fn rule_id(&self) -> &'static str {
        "MEM36-C"
    }

    fn description(&self) -> &'static str {
        "Do not modify the alignment of objects by calling realloc()"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        self.rule_id()
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: find all pointers allocated with aligned_alloc
        let mut aligned_pointers = HashSet::new();
        self.find_aligned_allocs(root, source, &mut aligned_pointers);

        // Second pass: find realloc calls on those pointers
        self.find_realloc_violations(root, source, &aligned_pointers, &mut violations);

        violations
    }
}

impl Mem36C {
    fn find_aligned_allocs(
        &self,
        node: &Node,
        source: &str,
        aligned_pointers: &mut HashSet<String>,
    ) {
        for n in
            query::find_descendants_of_kinds(*node, &["assignment_expression", "init_declarator"])
        {
            // Check if the right side is an aligned_alloc call
            if let Some(right) = n
                .child_by_field_name("right")
                .or_else(|| n.child_by_field_name("value"))
            {
                if self.is_aligned_alloc_call(&right, source) {
                    // Extract the variable name on the left side
                    if let Some(left) = n
                        .child_by_field_name("left")
                        .or_else(|| n.child_by_field_name("declarator"))
                    {
                        let var_name = self.extract_variable_name(&left, source);
                        if !var_name.is_empty() {
                            aligned_pointers.insert(var_name);
                        }
                    }
                }
            }
        }
    }

    fn find_realloc_violations(
        &self,
        node: &Node,
        source: &str,
        aligned_pointers: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);

                if func_name == "realloc" {
                    // Get the first argument (the pointer)
                    if let Some(args) = n.child_by_field_name("arguments") {
                        if let Some(ptr_arg) = self.get_first_argument(&args, source) {
                            // Check if this pointer was allocated with aligned_alloc
                            if aligned_pointers.contains(&ptr_arg) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: self.severity(),
                                    message: format!(
                                        "realloc() called on pointer '{}' that was allocated with aligned_alloc(), which may change alignment",
                                        ptr_arg
                                    ),
                                    file_path: String::new(),
                                    line: n.start_position().row + 1,
                                    column: n.start_position().column + 1,
                                    suggestion: Some(
                                        "Use aligned_alloc() with memcpy() instead of realloc() to preserve alignment".to_string()
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

    fn is_aligned_alloc_call(&self, node: &Node, source: &str) -> bool {
        // Check for cast_expression wrapping aligned_alloc
        let mut check_node = *node;
        if node.kind() == "cast_expression" {
            if let Some(value) = node.child_by_field_name("value") {
                check_node = value;
            }
        }

        if check_node.kind() == "call_expression" {
            if let Some(func) = check_node.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);
                return func_name == "aligned_alloc";
            }
        }

        false
    }

    fn extract_variable_name(&self, node: &Node, source: &str) -> String {
        match node.kind() {
            "identifier" => get_node_text(node, source).to_string(),
            "pointer_declarator" => {
                if let Some(decl) = node.child_by_field_name("declarator") {
                    self.extract_variable_name(&decl, source)
                } else {
                    String::new()
                }
            }
            _ => {
                // Try to find an identifier child
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "identifier" {
                        return get_node_text(&child, source).to_string();
                    }
                }
                String::new()
            }
        }
    }

    fn get_first_argument(&self, args_node: &Node, source: &str) -> Option<String> {
        let mut cursor = args_node.walk();
        for child in args_node.children(&mut cursor) {
            if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                return Some(get_node_text(&child, source).trim().to_string());
            }
        }
        None
    }
}
