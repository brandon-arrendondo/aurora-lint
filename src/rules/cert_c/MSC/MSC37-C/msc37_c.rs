//! MSC37-C: Ensure that control never reaches the end of a non-void function
//!
//! This rule addresses undefined behavior that occurs when a non-void function
//! completes without executing a return statement. If control reaches the closing
//! brace of a non-void function without evaluating a return statement, using the
//! return value is undefined behavior.
//!
//! ## Non-compliant examples:
//!
//! **Missing return statement:**
//! ```c
//! int get_value(void) {
//!     // No return statement - undefined behavior
//! }
//! ```
//!
//! **Return missing in some paths:**
//! ```c
//! int check_password(const char *password) {
//!     if (strcmp(password, "secret") == 0) {
//!         return 1;  // Match
//!     }
//!     // No return for mismatch case - undefined behavior
//! }
//! ```
//!
//! ## Compliant solutions:
//!
//! **Add explicit return:**
//! ```c
//! int get_value(void) {
//!     return 42;
//! }
//! ```
//!
//! **Return on all paths:**
//! ```c
//! int check_password(const char *password) {
//!     if (strcmp(password, "secret") == 0) {
//!         return 1;  // Match
//!     }
//!     return 0;  // No match
//! }
//! ```
//!
//! **Exception - main() implicitly returns 0:**
//! ```c
//! int main(void) {
//!     printf("Hello World\n");
//!     // Implicitly returns 0 - compliant per C standard
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Msc37C;

impl Msc37C {
    pub fn new() -> Self {
        Self
    }

    /// Check if a type is void
    fn is_void_type(&self, type_node: &Node, source: &str) -> bool {
        let type_text = get_node_text(type_node, source);
        type_text.trim() == "void"
    }

    /// Check if any direct child of function_definition is "void".
    /// Handles cases like `MACRO void func()` where a macro precedes void and
    /// tree-sitter assigns the macro as the type field. The actual "void" keyword
    /// ends up in an ERROR node since tree-sitter doesn't expect two type specifiers.
    fn has_void_specifier(&self, func_def: &Node, source: &str) -> bool {
        for i in 0..func_def.child_count() {
            if let Some(child) = func_def.child(i) {
                if get_node_text(&child, source).trim() == "void" {
                    return true;
                }
            }
        }
        false
    }

    /// Check if a function is main()
    fn is_main_function(&self, declarator: &Node, source: &str) -> bool {
        // Look for function_declarator with name "main"
        if let Some(func_declarator) = self.find_function_declarator(declarator) {
            if let Some(name_node) = func_declarator.child_by_field_name("declarator") {
                let name = get_node_text(&name_node, source);
                return name.trim() == "main";
            }
        }
        false
    }

    /// Find function_declarator node in declarator tree
    fn find_function_declarator<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        if node.kind() == "function_declarator" {
            return Some(*node);
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(found) = self.find_function_declarator(&child) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// Check if function body contains any return statement
    fn has_return_statement(&self, node: &Node) -> bool {
        query::find_first_descendant(*node, |n| n.kind() == "return_statement").is_some()
    }

    /// Check if the last statement in a compound statement is a return
    fn ends_with_return(&self, compound_stmt: &Node) -> bool {
        // Get the last non-brace, non-comment, non-preprocessor child.
        // Comments (e.g., `return val; // note`) and preprocessor directives
        // after a return would otherwise become the "last child" and cause false positives.
        let mut last_stmt = None;
        for i in 0..compound_stmt.child_count() {
            if let Some(child) = compound_stmt.child(i) {
                let kind = child.kind();
                if kind == "{" || kind == "}" || kind == "comment" || kind.starts_with("preproc_") {
                    continue;
                }
                last_stmt = Some(child);
            }
        }

        if let Some(stmt) = last_stmt {
            match stmt.kind() {
                "return_statement" => true,
                "if_statement" | "switch_statement" => {
                    // Check if all branches end with return
                    self.all_branches_return(&stmt)
                }
                "compound_statement" => self.ends_with_return(&stmt),
                _ => false,
            }
        } else {
            false
        }
    }

    /// Check if all branches of a conditional statement return
    fn all_branches_return(&self, node: &Node) -> bool {
        match node.kind() {
            "if_statement" => {
                // Must have both consequence and alternative, both returning
                if let Some(consequence) = node.child_by_field_name("consequence") {
                    let consequence_returns = self.statement_returns(&consequence);

                    if let Some(alternative) = node.child_by_field_name("alternative") {
                        let alternative_returns = self.statement_returns(&alternative);
                        return consequence_returns && alternative_returns;
                    }
                }
                false
            }
            "switch_statement" => {
                // Basic check: has default case and all cases return
                // This is a simplification - full analysis would be more complex
                self.has_return_statement(node)
            }
            _ => false,
        }
    }

    /// Check if a statement returns
    fn statement_returns(&self, stmt: &Node) -> bool {
        match stmt.kind() {
            "return_statement" => true,
            "compound_statement" => self.ends_with_return(stmt),
            "if_statement" | "switch_statement" => self.all_branches_return(stmt),
            "else_clause" => {
                // else_clause wraps the actual statement (compound_statement or single stmt)
                for i in 0..stmt.child_count() {
                    if let Some(child) = stmt.child(i) {
                        if child.kind() != "else" {
                            return self.statement_returns(&child);
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Check a function definition for missing returns
    fn check_function_definition(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() != "function_definition" {
            return;
        }

        // Get return type
        let type_node = match node.child_by_field_name("type") {
            Some(n) => n,
            None => return,
        };

        // Skip void functions — also check for void as a sibling specifier
        // to handle macros preceding void (e.g., STATIC void func())
        if self.is_void_type(&type_node, source) || self.has_void_specifier(node, source) {
            return;
        }

        // Skip phantom "functions" from preprocessor-broken else-if chains.
        // When `else if (...)` appears inside #ifdef with no preceding `if` in
        // the same scope, tree-sitter may misparse it as a function definition
        // with "else" as the type specifier.
        let type_text = get_node_text(&type_node, source);
        let type_trimmed = type_text.trim();
        if matches!(
            type_trimmed,
            "else" | "if" | "while" | "for" | "do" | "switch" | "case" | "default" | "return"
        ) {
            return;
        }

        // Get declarator
        let declarator = match node.child_by_field_name("declarator") {
            Some(d) => d,
            None => return,
        };

        // Exception: main() can implicitly return 0
        if self.is_main_function(&declarator, source) {
            return;
        }

        // Get function body
        let body = match node.child_by_field_name("body") {
            Some(b) => b,
            None => return,
        };

        // Check if function has any return statement
        if !self.has_return_statement(&body) {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: "Non-void function has no return statement. Control reaching the end of a non-void function without returning a value is undefined behavior.".to_string(),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some(
                    "Add a return statement on all execution paths of this function".to_string()
                ),
                ..Default::default()
            });
            return;
        }

        // Check if function body ends with return or all branches return
        if !self.ends_with_return(&body) {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: "Non-void function may reach end without returning a value. Ensure all execution paths have explicit return statements.".to_string(),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some(
                    "Add return statements to ensure all execution paths return a value".to_string()
                ),
                ..Default::default()
            });
        }
    }
}

impl CertRule for Msc37C {
    fn rule_id(&self) -> &'static str {
        "MSC37-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that control never reaches the end of a non-void function"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MSC37-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Msc37C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check function definitions
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function_definition(&func, source, violations);
        }
    }
}
