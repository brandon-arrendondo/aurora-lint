use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Exp30C;

impl CertRule for Exp30C {
    fn rule_id(&self) -> &'static str {
        "EXP30-C"
    }

    fn description(&self) -> &'static str {
        "Do not depend on the order of evaluation for side effects"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP30-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        let kinds = [
            "call_expression",
            "binary_expression",
            "assignment_expression",
        ];
        for n in query::find_descendants_of_kinds(*node, &kinds) {
            // Check function calls for unsequenced modifications
            if n.kind() == "call_expression" {
                self.check_function_arguments(&n, source, &mut violations);
            }

            // Check binary expressions for unsequenced modifications
            if n.kind() == "binary_expression" || n.kind() == "assignment_expression" {
                self.check_expression_for_unsequenced_effects(&n, source, &mut violations);
            }
        }

        violations
    }
}

impl Exp30C {
    /// Check function arguments for variables that are both modified and read
    fn check_function_arguments(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(args) = node.child_by_field_name("arguments") {
            let mut modified_vars = HashSet::new();
            let mut read_vars = HashSet::new();
            let mut function_calls: Vec<Node> = Vec::new();

            // Collect all arguments
            for i in 0..args.child_count() {
                if let Some(arg) = args.child(i) {
                    if arg.kind() == "," {
                        continue;
                    }

                    // Track function calls for global side effect analysis
                    if arg.kind() == "call_expression" {
                        function_calls.push(arg);
                    }

                    // Check if this argument modifies a variable (++, --, or assignment)
                    let mods = self.find_modifications(&arg, source);
                    modified_vars.extend(mods);

                    // Check if this argument reads a variable
                    let reads = self.find_variable_reads(&arg, source);
                    read_vars.extend(reads);
                }
            }

            // Find variables that are both modified and read
            let conflicts: Vec<_> = modified_vars.intersection(&read_vars).collect();

            if !conflicts.is_empty() {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Variable(s) {} modified and accessed in unsequenced function arguments",
                        conflicts
                            .iter()
                            .map(|s| format!("'{}'", s))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(
                        "Separate the modification from the function call".to_string(),
                    ),
                    ..Default::default()
                });
            }

            // Check if multiple function calls in arguments might have side effects
            // This detects cases like c(a(), b()) where both a() and b() might modify globals
            if function_calls.len() >= 2 {
                // Check if any function calls could potentially have side effects
                // (we conservatively assume they might modify global state)
                let has_potential_side_effects = function_calls.iter().any(|call| {
                    // If we can't prove it's side-effect-free, assume it might have side effects
                    !self.is_known_pure_function(call, source)
                });

                if has_potential_side_effects {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: "Multiple function calls with potential side effects in unsequenced arguments".to_string(),
                        file_path: String::new(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        suggestion: Some(
                            "Evaluate function calls in separate statements to guarantee ordering".to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check if a function is known to be pure (no side effects)
    /// This is conservative - we assume unknown functions might have side effects
    fn is_known_pure_function(&self, call_node: &Node, source: &str) -> bool {
        if let Some(func) = call_node.child_by_field_name("function") {
            let func_name = ast_utils::get_node_text(&func, source);

            // Known pure functions (read-only, no global state modification)
            let pure_functions = [
                "abs", "labs", "llabs", "fabs", "fabsf", "fabsl", "ceil", "floor", "round",
                "trunc", "sqrt", "sqrtf", "sqrtl", "sin", "cos", "tan", "asin", "acos", "atan",
                "atan2", "sinh", "cosh", "tanh", "exp", "log", "log10", "log2", "pow", "fmod",
                "fmax", "fmin", "strlen", "strcmp", "strncmp", "strchr", "strstr", "isalpha",
                "isdigit", "isalnum", "isspace", "isupper", "islower", "toupper", "tolower",
            ];

            return pure_functions.contains(&func_name);
        }
        false
    }

    /// Check an expression for unsequenced side effects (e.g., i + b[++i])
    fn check_expression_for_unsequenced_effects(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // For assignment expressions (x = expr), the RHS is fully evaluated before
        // the LHS write (C11 6.5.16). So `x = f(x)` is well-defined. Only flag
        // when the RHS itself contains unsequenced modifications (e.g., `a[i] = i++`).
        if node.kind() == "assignment_expression" {
            // Get modifications from RHS subexpressions only (++, --, compound assign)
            let rhs_mods = if let Some(right) = node.child_by_field_name("right") {
                self.find_modifications(&right, source)
            } else {
                HashSet::new()
            };
            // If RHS has no modifications beyond the assignment itself, it's safe
            if rhs_mods.is_empty() {
                return;
            }
            // Check if RHS modifications conflict with LHS or other reads
            let read_vars = self.find_variable_reads(node, source);
            let conflicts: Vec<_> = rhs_mods.intersection(&read_vars).collect();
            if !conflicts.is_empty() {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Variable(s) {} modified and accessed without sequence point",
                        conflicts
                            .iter()
                            .map(|s| format!("'{}'", s))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(
                        "Separate the modification into a separate statement".to_string(),
                    ),
                    ..Default::default()
                });
            }
            return;
        }

        let modified_vars = self.find_modifications(node, source);
        let read_vars = self.find_variable_reads(node, source);

        // Find variables that are both modified and read
        let conflicts: Vec<_> = modified_vars.intersection(&read_vars).collect();

        if !conflicts.is_empty() {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: format!(
                    "Variable(s) {} modified and accessed without sequence point",
                    conflicts
                        .iter()
                        .map(|s| format!("'{}'", s))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some("Separate the modification into a separate statement".to_string()),
                ..Default::default()
            });
        }
    }

    /// Find variables that are modified in an expression (++, --, assignment)
    fn find_modifications(&self, node: &Node, source: &str) -> HashSet<String> {
        let mut vars = HashSet::new();

        for n in
            query::find_descendants_of_kinds(*node, &["update_expression", "assignment_expression"])
        {
            // Check for update expressions (++, --)
            if n.kind() == "update_expression" {
                if let Some(arg) = n.child_by_field_name("argument") {
                    if arg.kind() == "identifier" {
                        vars.insert(ast_utils::get_node_text(&arg, source).to_string());
                    }
                }
            }

            // Check for assignment expressions
            if n.kind() == "assignment_expression" {
                if let Some(left) = n.child_by_field_name("left") {
                    if left.kind() == "identifier" {
                        vars.insert(ast_utils::get_node_text(&left, source).to_string());
                    }
                }
            }
        }

        vars
    }

    /// Find variables that are read in an expression (excluding modifications)
    fn find_variable_reads(&self, node: &Node, source: &str) -> HashSet<String> {
        let mut vars = HashSet::new();

        // Don't count modifications as reads for this purpose
        if node.kind() == "update_expression" {
            // Skip the argument of ++ or --, but check other parts
            return vars;
        }

        if node.kind() == "assignment_expression" {
            // Only check the right side for reads
            if let Some(right) = node.child_by_field_name("right") {
                vars.extend(self.find_variable_reads(&right, source));
            }
            return vars;
        }

        // Check for identifiers that are being read
        if node.kind() == "identifier" {
            // Make sure this isn't the target of an assignment or update
            if let Some(parent) = node.parent() {
                if parent.kind() == "update_expression" {
                    return vars; // This is being modified, not read
                }
                if parent.kind() == "assignment_expression" {
                    if let Some(left) = parent.child_by_field_name("left") {
                        if left.id() == node.id() {
                            return vars; // This is the left side of assignment
                        }
                    }
                }
            }

            vars.insert(ast_utils::get_node_text(node, source).to_string());
        }

        // Recursively check children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                vars.extend(self.find_variable_reads(&child, source));
            }
        }

        vars
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_c_code(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&crate::parser::c_language())
            .expect("Error loading C grammar");
        parser.parse(source, None).expect("Error parsing C code")
    }

    #[test]
    fn test_unsequenced_in_expression() {
        let code = r#"
void func(int i, int *b) {
    int a = i + b[++i];
}
"#;
        let tree = parse_c_code(code);
        let rule = Exp30C;
        let violations = rule.check(&tree.root_node(), code);
        assert!(
            !violations.is_empty(),
            "Should detect unsequenced side effect in expression"
        );
    }

    #[test]
    fn test_unsequenced_in_function_args() {
        let code = r#"
extern void func(int i, int j);

void f(int i) {
    func(i++, i);
}
"#;
        let tree = parse_c_code(code);
        let rule = Exp30C;
        let violations = rule.check(&tree.root_node(), code);
        assert!(
            !violations.is_empty(),
            "Should detect unsequenced side effect in function arguments"
        );
    }

    #[test]
    fn test_sequenced_modification() {
        let code = r#"
void func(int i, int *b) {
    int a;
    ++i;
    a = i + b[i];
}
"#;
        let tree = parse_c_code(code);
        let rule = Exp30C;
        let violations = rule.check(&tree.root_node(), code);
        assert!(
            violations.is_empty(),
            "Should not flag properly sequenced operations"
        );
    }
}
