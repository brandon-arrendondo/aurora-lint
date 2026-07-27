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
use std::collections::HashSet;
use tree_sitter::Node;

/// Standard/POSIX functions that never return to their caller, so a call to
/// one of them as a function's last statement satisfies MSC37-C the same
/// way an explicit return would (control can't fall off the end).
const STDLIB_NORETURN_FUNCTIONS: &[&str] = &["exit", "_Exit", "abort", "quick_exit", "longjmp"];

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

    /// Collect names of functions declared or defined `_Noreturn` anywhere
    /// in the translation unit, so a trailing call to one of them can be
    /// recognized as equivalent to a return (MSC37-C's own compliant
    /// example: a switch covering all enum values followed by a call to a
    /// `_Noreturn` fallback function, with no return after it).
    fn collect_noreturn_function_names(root: &Node, source: &str) -> HashSet<String> {
        let mut names = HashSet::new();
        for node in query::find_descendants_of_kinds(*root, &["declaration", "function_definition"])
        {
            let mut cursor = node.walk();
            let is_noreturn = node.children(&mut cursor).any(|c| {
                c.kind() == "type_qualifier" && get_node_text(&c, source).trim() == "_Noreturn"
            });
            if !is_noreturn {
                continue;
            }
            if let Some(declarator) = node.child_by_field_name("declarator") {
                if let Some(func_declarator) = Self::find_function_declarator_static(&declarator) {
                    if let Some(name_node) = func_declarator.child_by_field_name("declarator") {
                        names.insert(get_node_text(&name_node, source).trim().to_string());
                    }
                }
            }
        }
        names
    }

    /// Non-method variant of `find_function_declarator` (needed in a
    /// static/associated-function context above).
    fn find_function_declarator_static<'a>(node: &Node<'a>) -> Option<Node<'a>> {
        if node.kind() == "function_declarator" {
            return Some(*node);
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(found) = Self::find_function_declarator_static(&child) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// True if `node` is an `expression_statement` wrapping a call to a
    /// known-noreturn function (stdlib or `_Noreturn`-declared in this
    /// file).
    fn is_noreturn_call_statement(
        &self,
        node: &Node,
        source: &str,
        noreturn_names: &HashSet<String>,
    ) -> bool {
        if node.kind() != "expression_statement" {
            return false;
        }
        let Some(call) = node.child(0).filter(|c| c.kind() == "call_expression") else {
            return false;
        };
        let Some(function) = call.child_by_field_name("function") else {
            return false;
        };
        let name = get_node_text(&function, source).trim().to_string();
        STDLIB_NORETURN_FUNCTIONS.contains(&name.as_str()) || noreturn_names.contains(&name)
    }

    /// Check if the last statement in a compound statement is a return
    /// (possibly through nested if/switch branches that all return).
    ///
    /// `ends_with_return`/`all_branches_return`/`statement_returns` used to
    /// be three mutually recursive functions chaining through nested
    /// if/else-if and compound-statement nesting -- a long else-if chain
    /// would cost one native call frame per link (the same hostap-style
    /// risk class as the original ARR00-C/MEM33-C bug, task 153). They're
    /// unified here into one postorder evaluator using an explicit
    /// instruction/value stack instead of recursion: `if_statement` needs
    /// BOTH its consequence and alternative evaluated before it can AND
    /// them together, so this uses the classic stack-machine technique
    /// (push `Eval` work, push an `And` combinator that pops two already-
    /// computed results) rather than a plain node-only stack.
    fn ends_with_return(
        &self,
        compound_stmt: &Node,
        source: &str,
        noreturn_names: &HashSet<String>,
    ) -> bool {
        self.stmt_returns(compound_stmt, source, noreturn_names)
    }

    fn stmt_returns(&self, root: &Node, source: &str, noreturn_names: &HashSet<String>) -> bool {
        enum Op<'a> {
            Eval(Node<'a>),
            And,
        }

        let mut ops: Vec<Op> = vec![Op::Eval(*root)];
        let mut values: Vec<bool> = Vec::new();

        while let Some(op) = ops.pop() {
            match op {
                Op::Eval(node) => match node.kind() {
                    "return_statement" => values.push(true),
                    "compound_statement" => {
                        // Last non-brace, non-comment, non-preprocessor child.
                        // Comments (e.g., `return val; // note`) and
                        // preprocessor directives after a return would
                        // otherwise become the "last child" and cause false
                        // positives.
                        let mut last_stmt = None;
                        for i in 0..node.child_count() {
                            if let Some(child) = node.child(i) {
                                let kind = child.kind();
                                if kind == "{"
                                    || kind == "}"
                                    || kind == "comment"
                                    || kind.starts_with("preproc_")
                                {
                                    continue;
                                }
                                last_stmt = Some(child);
                            }
                        }
                        match last_stmt {
                            Some(stmt)
                                if self.is_noreturn_call_statement(
                                    &stmt,
                                    source,
                                    noreturn_names,
                                ) =>
                            {
                                values.push(true);
                            }
                            Some(stmt) => ops.push(Op::Eval(stmt)),
                            None => values.push(false),
                        }
                    }
                    "if_statement" => {
                        // Must have both consequence and alternative, both returning
                        match (
                            node.child_by_field_name("consequence"),
                            node.child_by_field_name("alternative"),
                        ) {
                            (Some(consequence), Some(alternative)) => {
                                ops.push(Op::And);
                                ops.push(Op::Eval(alternative));
                                ops.push(Op::Eval(consequence));
                            }
                            _ => values.push(false),
                        }
                    }
                    "switch_statement" => {
                        // Basic check: has a return statement anywhere.
                        // This is a simplification - full analysis would be more complex
                        values.push(self.has_return_statement(&node));
                    }
                    "else_clause" => {
                        // else_clause wraps the actual statement (compound_statement or single stmt)
                        let inner = (0..node.child_count())
                            .filter_map(|i| node.child(i))
                            .find(|child| child.kind() != "else");
                        match inner {
                            Some(child) => ops.push(Op::Eval(child)),
                            None => values.push(false),
                        }
                    }
                    _ => values.push(false),
                },
                Op::And => {
                    let b = values.pop().unwrap_or(false);
                    let a = values.pop().unwrap_or(false);
                    values.push(a && b);
                }
            }
        }

        values.pop().unwrap_or(false)
    }

    /// Check a function definition for missing returns
    fn check_function_definition(
        &self,
        node: &Node,
        source: &str,
        noreturn_names: &HashSet<String>,
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
        if !self.ends_with_return(&body, source, noreturn_names) {
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

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Msc37C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let noreturn_names = Self::collect_noreturn_function_names(node, source);
        // Check function definitions
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function_definition(&func, source, &noreturn_names, violations);
        }
    }
}
