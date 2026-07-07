//! EXP10-C: Do not depend on the order of evaluation of subexpressions or the order
//! in which side effects take place
//!
//! The order of evaluation of subexpressions is unspecified in C. Multiple function
//! calls with side effects in the same expression can lead to undefined behavior.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int x = f(1) + f(2);  // Order of f(1) and f(2) is unspecified
//! ```
//!
//! **Compliant:**
//! ```c
//! int x = f(1);
//! x += f(2);  // Side effects are sequenced
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Exp10C;

impl CertRule for Exp10C {
    fn rule_id(&self) -> &'static str {
        "EXP10-C"
    }

    fn description(&self) -> &'static str {
        "Do not depend on the order of evaluation of subexpressions or the order in which side effects take place"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "EXP10-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.find_unsequenced_side_effects(node, source, violations);
    }
}

impl Exp10C {
    /// Find expressions with multiple function calls that could have unsequenced side effects
    fn find_unsequenced_side_effects(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kinds(
            *node,
            &[
                "binary_expression",
                "call_expression",
                "subscript_expression",
            ],
        ) {
            self.check_unsequenced_node(&n, source, violations);
        }
    }

    /// Check a single node (binary_expression / call_expression / subscript_expression)
    /// for unsequenced side effects
    fn check_unsequenced_node(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check binary expressions for multiple function calls
        if node.kind() == "binary_expression" {
            // C guarantees left-to-right evaluation for logical operators (&&, ||)
            // with a sequence point between operands.  These are NOT unsequenced.
            let is_sequenced_op = node
                .child_by_field_name("operator")
                .map(|op| {
                    let op_text = get_node_text(&op, source);
                    op_text == "||" || op_text == "&&"
                })
                .unwrap_or(false);

            let call_count = self.count_function_calls(node, source);
            if call_count >= 2 && !is_sequenced_op {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    message: format!(
                        "Expression contains {} function calls with potentially unsequenced side effects. \
                         Order of evaluation is unspecified.",
                        call_count
                    ),
                    severity: self.severity(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    file_path: String::new(),
                    suggestion: Some(
                        "Separate function calls into distinct statements to ensure defined evaluation order"
                            .to_string(),
                    ),
                    requires_manual_review: None,
                });
            }
        }

        // Check function call expressions that themselves contain multiple function calls
        if node.kind() == "call_expression" {
            if let Some(args) = node.child_by_field_name("arguments") {
                let call_count = self.count_function_calls(&args, source);
                if call_count >= 2 {
                    let node_text = get_node_text(node, source);
                    // Only flag if this looks like the complex pattern with array subscript
                    if node_text.contains("[") && node_text.contains("]") {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: format!(
                                "Function call with {} nested function calls. \
                                 Order of evaluation is unspecified.",
                                call_count
                            ),
                            severity: self.severity(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            file_path: String::new(),
                            suggestion: Some(
                                "Store function results in temporary variables before use"
                                    .to_string(),
                            ),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }

        // Also check for complex pointer subscript patterns
        if node.kind() == "subscript_expression" {
            let total_calls = self.count_function_calls(node, source);
            if total_calls >= 2 {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    message: format!(
                        "Subscript expression with {} function calls. \
                         Order of evaluation is unspecified.",
                        total_calls
                    ),
                    severity: self.severity(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    file_path: String::new(),
                    suggestion: Some(
                        "Store intermediate results in temporary variables".to_string(),
                    ),
                    requires_manual_review: None,
                });
            }
        }
    }

    /// Count the number of non-pure function calls in a subtree.
    /// Pure functions (abs, sqrt, strlen, etc.) have no side effects so their evaluation
    /// order doesn't matter — counting them creates false positives on safe patterns like
    /// `if (abs(data) <= sqrt(CHAR_MAX))`.
    fn count_function_calls(&self, node: &Node, source: &str) -> usize {
        query::find_descendants(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            // Check if this is a known pure function — if so, skip it
            let is_pure = n
                .child_by_field_name("function")
                .map(|func| self.is_pure_function(get_node_text(&func, source)))
                .unwrap_or(false);
            !is_pure
        })
        .len()
    }

    /// Check if a function is known to be pure (no side effects).
    /// Pure functions do not need sequencing — calling them in any order
    /// produces the same result without affecting shared state.
    fn is_pure_function(&self, name: &str) -> bool {
        matches!(
            name,
            // Math functions (C standard)
            "abs" | "fabs" | "fabsf" | "fabsl" | "labs" | "llabs"
            | "sqrt" | "sqrtf" | "sqrtl"
            | "sin" | "sinf" | "sinl"
            | "cos" | "cosf" | "cosl"
            | "tan" | "tanf" | "tanl"
            | "asin" | "acos" | "atan" | "atan2"
            | "ceil" | "ceilf" | "ceill"
            | "floor" | "floorf" | "floorl"
            | "round" | "roundf" | "roundl"
            | "fmod" | "fmodf" | "fmodl"
            | "pow" | "powf" | "powl"
            | "exp" | "expf" | "expl"
            | "log" | "logf" | "logl"
            | "log2" | "log10"
            | "hypot" | "hypotf"
            | "cbrt" | "cbrtf"
            | "trunc" | "truncf" | "truncl"
            // String query functions (read-only)
            | "strlen" | "wcslen" | "strnlen"
            | "strcmp" | "strncmp" | "strcasecmp" | "strncasecmp"
            | "memcmp"
            | "strchr" | "strrchr" | "strstr"
            // Type testing
            | "isdigit" | "isalpha" | "isalnum" | "isspace" | "isupper" | "islower"
            | "isxdigit" | "isprint" | "ispunct" | "iscntrl"
            // Conversion (read-only)
            | "toupper" | "tolower"
            | "atoi" | "atol" | "atoll" | "atof"
            | "strtol" | "strtoul" | "strtoll" | "strtoull" | "strtod"
        )
    }
}
