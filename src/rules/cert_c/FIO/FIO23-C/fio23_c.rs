use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio23C;

impl CertRule for Fio23C {
    fn rule_id(&self) -> &'static str {
        "FIO23-C"
    }

    fn description(&self) -> &'static str {
        "Do not exit with unflushed data in stdout or stderr. Call fclose() or fflush() before exit/return."
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

        // Check if stdout/stderr are closed before return in main
        if self.has_main_return_without_fclose(root, source) {
            // Find the return statement in main
            if let Some((line, column)) = self.find_main_return(root) {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message:
                        "main() returns without calling fclose(stdout) - data may be unflushed"
                            .to_string(),
                    file_path: String::new(),
                    line,
                    column,
                    suggestion: Some(
                        "Call fclose(stdout) before return to ensure data is flushed".to_string(),
                    ),
                    requires_manual_review: Some(false),
                });
            }
        }

        // Check for printf in atexit handlers without prior fclose
        self.check_atexit_handlers(root, source, &mut violations);

        violations
    }
}

impl Fio23C {
    fn has_main_return_without_fclose(&self, root: &Node, source: &str) -> bool {
        // Find main function
        if let Some(main_func) = self.find_main_function(root, source) {
            // Check if there's fclose(stdout) before return
            if let Some(body) = main_func.child_by_field_name("body") {
                return !self.has_fclose_stdout(&body, source);
            }
        }
        false
    }

    fn find_main_function<'a>(&self, node: &Node<'a>, source: &str) -> Option<Node<'a>> {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "function_definition" {
                return false;
            }
            let Some(declarator) = n.child_by_field_name("declarator") else {
                return false;
            };
            self.find_identifier_in_declarator(&declarator)
                .is_some_and(|name_node| get_node_text(&name_node, source) == "main")
        })
    }

    fn find_identifier_in_declarator<'a>(&self, declarator: &Node<'a>) -> Option<Node<'a>> {
        if declarator.kind() == "identifier" {
            return Some(*declarator);
        }

        let mut cursor = declarator.walk();
        for child in declarator.children(&mut cursor) {
            if child.kind() == "identifier" {
                return Some(child);
            }
            if let Some(result) = self.find_identifier_in_declarator(&child) {
                return Some(result);
            }
        }
        None
    }

    fn has_fclose_stdout(&self, body: &Node, source: &str) -> bool {
        self.check_fclose_stdout_recursive(body, source)
    }

    fn check_fclose_stdout_recursive(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(func) = n.child_by_field_name("function") else {
                return false;
            };
            if get_node_text(&func, source) != "fclose" {
                return false;
            }
            let Some(args) = n.child_by_field_name("arguments") else {
                return false;
            };
            get_node_text(&args, source).contains("stdout")
        })
        .is_some()
    }

    fn find_main_return(&self, root: &Node) -> Option<(usize, usize)> {
        if let Some(main_func) = self.find_main_function_node(root) {
            if let Some(body) = main_func.child_by_field_name("body") {
                if let Some(return_stmt) = self.find_return_statement(&body) {
                    let line = return_stmt.start_position().row + 1;
                    let column = return_stmt.start_position().column + 1;
                    return Some((line, column));
                }
            }
        }
        None
    }

    fn find_main_function_node<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        query::find_first_descendant(*node, |n| {
            n.kind() == "function_definition"
                && n.child_by_field_name("declarator")
                    .is_some_and(|declarator| self.is_main_declarator(&declarator))
        })
    }

    fn is_main_declarator(&self, declarator: &Node) -> bool {
        if declarator.kind() == "identifier" {
            return true; // Simplified check
        }

        let mut cursor = declarator.walk();
        for child in declarator.children(&mut cursor) {
            if self.is_main_declarator(&child) {
                return true;
            }
        }
        false
    }

    fn find_return_statement<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        query::find_first_descendant(*node, |n| n.kind() == "return_statement")
    }

    fn check_atexit_handlers(
        &self,
        root: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // First check if main has fclose(stdout)
        let main_has_fclose = if let Some(main_func) = self.find_main_function(root, source) {
            if let Some(body) = main_func.child_by_field_name("body") {
                self.has_fclose_stdout(&body, source)
            } else {
                false
            }
        } else {
            false
        };

        // Only flag if main closes stdout AND there are atexit handlers with printf
        if !main_has_fclose {
            return;
        }

        // Find atexit() calls and track registered functions
        let atexit_funcs = self.find_atexit_functions(root, source);

        for func_name in atexit_funcs {
            // Find the function definition
            if let Some(func_node) = self.find_function_by_name(root, &func_name, source) {
                // Check if it has printf/fprintf without fclose before
                if self.has_printf_in_function(&func_node, source) {
                    let line = func_node.start_position().row + 1;
                    let column = func_node.start_position().column + 1;

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!("atexit handler '{}' contains printf after fclose(stdout) in main - output may be lost", func_name),
                        file_path: String::new(),
                        line,
                        column,
                        suggestion: Some("Do not call fclose(stdout) before atexit handlers that print".to_string()),
                        requires_manual_review: Some(true),
                    });
                }
            }
        }
    }

    fn find_atexit_functions(&self, node: &Node, source: &str) -> Vec<String> {
        let mut funcs = Vec::new();
        self.collect_atexit_functions(node, source, &mut funcs);
        funcs
    }

    fn collect_atexit_functions(&self, node: &Node, source: &str, funcs: &mut Vec<String>) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func) = n.child_by_field_name("function") {
                if get_node_text(&func, source) == "atexit" {
                    if let Some(args) = n.child_by_field_name("arguments") {
                        if let Some(arg) = self.get_first_arg(&args) {
                            let func_name = get_node_text(&arg, source).to_string();
                            funcs.push(func_name);
                        }
                    }
                }
            }
        }
    }

    fn get_first_arg<'a>(&self, arguments: &Node<'a>) -> Option<Node<'a>> {
        let mut cursor = arguments.walk();
        Self::find_first_non_punctuation(arguments.children(&mut cursor))
    }

    fn find_first_non_punctuation<'a>(iter: impl Iterator<Item = Node<'a>>) -> Option<Node<'a>> {
        iter.into_iter()
            .find(|child| child.kind() != "," && child.kind() != "(" && child.kind() != ")")
    }

    fn find_function_by_name<'a>(
        &self,
        node: &Node<'a>,
        name: &str,
        source: &str,
    ) -> Option<Node<'a>> {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "function_definition" {
                return false;
            }
            let Some(declarator) = n.child_by_field_name("declarator") else {
                return false;
            };
            self.find_identifier_in_declarator(&declarator)
                .is_some_and(|id| get_node_text(&id, source) == name)
        })
    }

    #[allow(dead_code)]
    fn has_print_without_prior_fclose(&self, func_node: &Node, source: &str) -> bool {
        // This method is no longer used but kept for completeness
        self.has_printf_in_function(func_node, source)
    }

    fn has_printf_in_function(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(func) = n.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&func, source);
            func_name == "printf" || func_name == "fprintf" || func_name == "puts"
        })
        .is_some()
    }
}
