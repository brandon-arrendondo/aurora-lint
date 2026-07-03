//! PRE02-C: Macro replacement lists should be parenthesized
//!
//! This rule addresses operator precedence issues when macros are used in expressions.
//! Without outer parentheses around the replacement list, operators in the macro can
//! interact unexpectedly with surrounding code.
//!
//! ## Non-compliant example:
//!
//! ```c
//! #define CUBE(X) (X) * (X) * (X)
//! int result = 81 / CUBE(i);  // Expands to 81 / (i) * (i) * (i) = wrong result!
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! #define CUBE(X) ((X) * (X) * (X))
//! int result = 81 / CUBE(i);  // Expands to 81 / ((i) * (i) * (i)) = correct!
//! ```
//!
//! ## Exceptions (No outer parentheses needed):
//!
//! 1. **Single identifier:**
//!    ```c
//!    #define MY_PID getpid()  // OK - single function call
//!    ```
//!
//! 2. **Array subscript:**
//!    ```c
//!    #define TOOFAR array[MAX_ARRAY_SIZE]  // OK - subscript operator
//!    ```
//!
//! 3. **Member access:**
//!    ```c
//!    #define NEXT_FREE block->next_free  // OK - member access
//!    ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pre02C;

impl Pre02C {
    pub fn new() -> Self {
        Self
    }

    /// Check if the replacement text is fully parenthesized
    fn is_fully_parenthesized(&self, text: &str) -> bool {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return false;
        }

        // Check if the entire text is wrapped in parentheses
        if !trimmed.starts_with('(') || !trimmed.ends_with(')') {
            return false;
        }

        // Verify that the opening and closing parentheses match
        // Count depth to ensure the first '(' matches the last ')'
        let mut depth = 0;
        let chars: Vec<char> = trimmed.chars().collect();

        for (i, &c) in chars.iter().enumerate() {
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
                // If depth becomes 0 before the last character, outer parens don't wrap everything
                if depth == 0 && i < chars.len() - 1 {
                    return false;
                }
            }
        }

        depth == 0
    }

    /// Check if the replacement is a single identifier (exception)
    fn is_single_identifier(&self, text: &str) -> bool {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return false;
        }

        // Single identifier: alphanumeric + underscore only
        // Could also be a function call like getpid()
        // Check if it's a simple identifier or function call without operators

        // If it contains binary operators, it's not a single identifier
        let operators = vec![
            "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", "&&", "||",
        ];
        for op in operators {
            if trimmed.contains(op) {
                return false;
            }
        }

        // Simple heuristic: if it's a function call or identifier, it's OK
        // Function calls have balanced parentheses and no operators outside
        true
    }

    /// Check if the replacement is a cast expression wrapping a fully parenthesized operand.
    /// Pattern: (type)(expr) where the entire operand after the cast is parenthesized.
    /// Example: (uint8_t)(a | b) — the cast prevents precedence issues.
    fn is_cast_with_parenthesized_operand(&self, text: &str) -> bool {
        let trimmed = text.trim();
        if !trimmed.starts_with('(') {
            return false;
        }
        // Find the closing ')' of the cast type
        let mut depth = 0;
        let mut cast_end = 0;
        for (i, c) in trimmed.char_indices() {
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
                if depth == 0 {
                    cast_end = i;
                    break;
                }
            }
        }
        if cast_end == 0 || cast_end >= trimmed.len() - 1 {
            return false;
        }
        // The cast type must look like a type name (letters, digits, underscores, spaces, *)
        let cast_type = &trimmed[1..cast_end];
        if cast_type.is_empty()
            || !cast_type
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == ' ' || c == '*')
        {
            return false;
        }
        // The rest after the cast must be a fully parenthesized expression
        let rest = trimmed[cast_end + 1..].trim();
        self.is_fully_parenthesized(rest)
    }

    /// Check if the replacement is a do{...}while(0) statement macro pattern.
    /// This is the CERT-C recommended approach for multi-statement macros and
    /// does not need outer parenthesization.
    fn is_do_while_zero_pattern(&self, text: &str) -> bool {
        let lower = text.trim().to_lowercase();
        lower.starts_with("do")
            && lower.contains("while")
            && (lower.ends_with("while(0)")
                || lower.ends_with("while (0)")
                || lower.ends_with("while(0u)")
                || lower.ends_with("while (0u)"))
    }

    /// Check if the replacement contains operators that need parenthesization
    fn contains_operators(&self, text: &str) -> bool {
        let trimmed = text.trim();

        // Binary operators
        let operators = vec![
            " + ", " - ", " * ", " / ", " % ", " & ", " | ", " ^ ", " << ", " >> ", " && ", " || ",
            " < ", " > ", " <= ", " >= ", " == ", " != ",
        ];

        for op in operators {
            if trimmed.contains(op) {
                return true;
            }
        }

        // Check for unary operators at the start
        // Note: Even standalone negative numbers like -1 should be parenthesized
        // because "x END_OF_FILE" becomes "x -1" (subtraction) if END_OF_FILE is defined as -1
        if trimmed.starts_with('-') || trimmed.starts_with('!') || trimmed.starts_with('~') {
            return true;
        }

        false
    }

    /// Check a macro definition for unparenthesized replacement list
    fn check_macro_definition(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check both preproc_def (object-like) and preproc_function_def (function-like)
        let is_object_macro = node.kind() == "preproc_def";
        let is_function_macro = node.kind() == "preproc_function_def";

        if !is_object_macro && !is_function_macro {
            return;
        }

        // Get the replacement/value text
        let value_node = match node.child_by_field_name("value") {
            Some(v) => v,
            None => return, // No replacement text
        };

        let raw_value_text = get_node_text(&value_node, source);

        // Strip trailing line comments — tree-sitter may include `// ...` in preproc_def value
        let value_text: &str = match raw_value_text.find("//") {
            Some(pos) => raw_value_text[..pos].trim_end(),
            None => raw_value_text,
        };

        // Check if it contains operators
        if !self.contains_operators(&value_text) {
            return; // No operators, no need for parentheses
        }

        // Check if it's a single identifier exception
        if self.is_single_identifier(&value_text) {
            return; // Exception applies
        }

        // Check if it's already fully parenthesized
        if self.is_fully_parenthesized(&value_text) {
            return; // Already compliant
        }

        // Exception: do{...}while(0) is the CERT-C recommended pattern for
        // multi-statement macros — parenthesization does not apply.
        if self.is_do_while_zero_pattern(&value_text) {
            return;
        }

        // Exception: cast expression wrapping a parenthesized operand, like
        // (uint8_t)(expr) or (int)(a + b). The cast binds tighter than any
        // binary operator, so there is no precedence issue in surrounding code.
        if self.is_cast_with_parenthesized_operand(&value_text) {
            return;
        }

        // Report violation
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: "Macro replacement list should be parenthesized to prevent operator precedence issues.".to_string(),
            file_path: String::new(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            suggestion: Some(format!(
                "Wrap the entire replacement list in parentheses: ({})",
                value_text.trim()
            )),
            ..Default::default()
        });
    }
}

impl CertRule for Pre02C {
    fn rule_id(&self) -> &'static str {
        "PRE02-C"
    }

    fn description(&self) -> &'static str {
        "Macro replacement lists should be parenthesized"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "PRE02-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for macro_node in
            query::find_descendants_of_kinds(*node, &["preproc_def", "preproc_function_def"])
        {
            self.check_macro_definition(&macro_node, source, &mut violations);
        }
        violations
    }
}
