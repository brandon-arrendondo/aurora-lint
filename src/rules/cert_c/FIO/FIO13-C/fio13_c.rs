use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Fio13C;

impl CertRule for Fio13C {
    fn rule_id(&self) -> &'static str {
        "FIO13-C"
    }

    fn description(&self) -> &'static str {
        "Never attempt to pushback more than one character via successive calls to ungetc()"
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

        // Track ungetc calls per FILE pointer
        let mut file_operations: HashMap<String, Vec<FileOp>> = HashMap::new();

        self.collect_operations(root, source, &mut file_operations);

        // Check for successive ungetc calls
        for (file_ptr, ops) in file_operations {
            let mut last_ungetc: Option<usize> = None;

            for op in ops {
                match op {
                    FileOp::Ungetc(line) => {
                        if let Some(prev_line) = last_ungetc {
                            // Found successive ungetc without intervening read
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: format!(
                                    "Multiple successive ungetc() calls on '{}' without intervening read (previous ungetc at line {})",
                                    file_ptr, prev_line + 1
                                ),
                                file_path: String::new(),
                                line: line + 1,
                                column: 0,
                                suggestion: Some("Insert a read operation (fgetc, fgets, etc.) between ungetc() calls".to_string()),
                                ..Default::default()
                            });
                        }
                        last_ungetc = Some(line);
                    }
                    FileOp::Read(_) => {
                        // Reset on read operation
                        last_ungetc = None;
                    }
                }
            }
        }

        violations
    }
}

impl Fio13C {
    fn collect_operations(
        &self,
        node: &Node,
        source: &str,
        file_operations: &mut HashMap<String, Vec<FileOp>>,
    ) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);

                if func_name == "ungetc" {
                    // Get the FILE* argument (second argument)
                    if let Some(args) = n.child_by_field_name("arguments") {
                        if let Some(file_arg) = self.get_nth_argument(&args, 1, source) {
                            let entry = file_operations.entry(file_arg.clone()).or_default();
                            entry.push(FileOp::Ungetc(n.start_position().row));
                        }
                    }
                } else if self.is_read_function(&func_name) {
                    // Get the FILE* argument
                    if let Some(args) = n.child_by_field_name("arguments") {
                        if let Some(file_arg) = self.get_file_argument(&args, &func_name, source) {
                            let entry = file_operations.entry(file_arg.clone()).or_default();
                            entry.push(FileOp::Read(n.start_position().row));
                        }
                    }
                }
            }
        }
    }

    fn get_nth_argument(&self, args_node: &Node, n: usize, source: &str) -> Option<String> {
        let mut count = 0;
        let mut cursor = args_node.walk();

        for child in args_node.children(&mut cursor) {
            if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                if count == n {
                    return Some(get_node_text(&child, source).trim().to_string());
                }
                count += 1;
            }
        }
        None
    }

    fn get_file_argument(&self, args_node: &Node, func_name: &str, source: &str) -> Option<String> {
        // Most read functions have FILE* as last or first argument
        match func_name {
            "fgetc" | "fgets" | "fread" | "fscanf" | "fgetpos" => {
                // FILE* is typically the last argument for these
                let mut last_arg = None;
                let mut cursor = args_node.walk();
                for child in args_node.children(&mut cursor) {
                    if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                        last_arg = Some(get_node_text(&child, source).trim().to_string());
                    }
                }
                last_arg
            }
            _ => self.get_nth_argument(args_node, 0, source),
        }
    }

    fn is_read_function(&self, func_name: &str) -> bool {
        matches!(
            func_name,
            "fgetc" | "fgets" | "fread" | "fscanf" | "getc" | "fgetpos" | "fsetpos"
        )
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum FileOp {
    Ungetc(usize), // line number
    Read(usize),   // line number
}
