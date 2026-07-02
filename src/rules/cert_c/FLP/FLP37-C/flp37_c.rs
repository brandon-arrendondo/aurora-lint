use crate::manifest::{RuleCategory, Severity};
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Flp37C;

impl CertRule for Flp37C {
    fn rule_id(&self) -> &'static str {
        "FLP37-C"
    }

    fn cert_id(&self) -> &'static str {
        "FLP37"
    }

    fn description(&self) -> &'static str {
        "Do not use object representations to compare floating-point values"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: collect struct definitions with floating-point fields
        let mut float_structs = HashMap::new();
        self.collect_float_structs(node, source, &mut float_structs);

        // Second pass: check memcmp calls with those structs
        self.check_memcmp_calls(node, source, &float_structs, &mut violations);

        violations
    }
}

impl Flp37C {
    fn collect_float_structs(
        &self,
        node: &Node,
        source: &str,
        float_structs: &mut HashMap<String, bool>,
    ) {
        for n in query::find_descendants_of_kind(*node, "struct_specifier") {
            if let Some((struct_name, has_float)) = self.check_struct_for_float(&n, source) {
                if has_float {
                    float_structs.insert(struct_name, true);
                }
            }
        }
    }

    fn check_struct_for_float(&self, node: &Node, source: &str) -> Option<(String, bool)> {
        let mut struct_name = None;
        let mut has_float = false;

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                "type_identifier" => {
                    struct_name = Some(get_node_text(&child, source).to_string());
                }
                "field_declaration_list" => {
                    has_float = self.has_float_field(&child, source);
                }
                _ => {}
            }
        }

        if let Some(name) = struct_name {
            return Some((name, has_float));
        }

        None
    }

    fn has_float_field(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            n.kind() == "primitive_type" && matches!(get_node_text(&n, source), "float" | "double")
        })
        .is_some()
    }

    fn check_memcmp_calls(
        &self,
        node: &Node,
        source: &str,
        float_structs: &HashMap<String, bool>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            let mut cursor = call.walk();
            let mut is_memcmp = false;

            for child in call.children(&mut cursor) {
                if child.kind() == "identifier" {
                    let func_name = get_node_text(&child, source);
                    if func_name == "memcmp" {
                        is_memcmp = true;
                        break;
                    }
                }
            }

            if is_memcmp {
                // Check if any argument involves a struct with float fields
                for child in call.children(&mut cursor) {
                    if child.kind() == "argument_list" {
                        if self.args_contain_float_struct(&child, source, float_structs) {
                            let start = call.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                file_path: String::new(),
                                message: "Using memcmp() on struct containing floating-point members. Floating-point values should be compared field-by-field, not by object representation.".to_string(),
                                line: start.row + 1,
                                column: start.column + 1,
                                severity: self.severity(),
                                suggestion: Some("Compare floating-point fields individually instead of using memcmp()".to_string()),
                                requires_manual_review: Some(false),
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    fn args_contain_float_struct(
        &self,
        node: &Node,
        source: &str,
        float_structs: &HashMap<String, bool>,
    ) -> bool {
        // Check if this node or its descendants reference a struct with floats
        // via sizeof(struct S) patterns.
        query::find_descendants_of_kind(*node, "sizeof_expression")
            .into_iter()
            .any(|sizeof_node| {
                let mut cursor = sizeof_node.walk();
                let type_descriptors: Vec<_> = sizeof_node
                    .children(&mut cursor)
                    .filter(|c| c.kind() == "type_descriptor")
                    .collect();
                type_descriptors.into_iter().any(|type_desc| {
                    self.extract_struct_name(&type_desc, source)
                        .is_some_and(|name| float_structs.contains_key(&name))
                })
            })
    }

    fn extract_struct_name(&self, node: &Node, source: &str) -> Option<String> {
        let found = query::find_first_descendant(*node, |n| {
            (n.kind() == "struct_specifier" || n.kind() == "type_identifier")
                && n.children(&mut n.walk())
                    .any(|c| c.kind() == "type_identifier")
        })?;
        let mut cursor = found.walk();
        let name = found
            .children(&mut cursor)
            .find(|c| c.kind() == "type_identifier")
            .map(|c| get_node_text(&c, source).to_string());
        name
    }
}
