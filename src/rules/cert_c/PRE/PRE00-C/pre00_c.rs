use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pre00C;

impl CertRule for Pre00C {
    fn rule_id(&self) -> &'static str {
        "PRE00-C"
    }

    fn description(&self) -> &'static str {
        "Prefer inline or static functions to function-like macros"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        self.rule_id()
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(root, source, &mut violations);
        violations
    }
}

impl Pre00C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Only flag preproc_function_def (true function-like macros)
        // with parameters that are evaluated more than once (multi-evaluation risk)
        for n in query::find_descendants_of_kind(*node, "preproc_function_def") {
            if self.has_multi_evaluation_risk(&n, source) {
                let macro_name = n
                    .child_by_field_name("name")
                    .map(|c| get_node_text(&c, source))
                    .unwrap_or("unknown");
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Function-like macro '{}' evaluates parameter(s) multiple times; \
                         prefer inline or static functions for type safety",
                        macro_name
                    ),
                    file_path: String::new(),
                    line: n.start_position().row + 1,
                    column: n.start_position().column + 1,
                    suggestion: None,
                    requires_manual_review: None,
                });
            }
        }
    }

    /// Check if a function-like macro has unsafe patterns:
    /// multi-evaluation of parameters or side effects in the body.
    fn has_multi_evaluation_risk(&self, node: &Node, source: &str) -> bool {
        let body = match node.child_by_field_name("value") {
            Some(v) => get_node_text(&v, source).to_string(),
            None => return false,
        };

        // Side effects in body: increment/decrement operators
        if body.contains("++") || body.contains("--") {
            return true;
        }

        // Multi-evaluation: any parameter used more than once
        let params = Self::extract_macro_params(node, source);
        for param in &params {
            if Self::count_word_occurrences(&body, param) > 1 {
                return true;
            }
        }
        false
    }

    /// Extract parameter names from a preproc_function_def's parameters node.
    fn extract_macro_params(node: &Node, source: &str) -> Vec<String> {
        let mut params = Vec::new();
        if let Some(params_node) = node.child_by_field_name("parameters") {
            for i in 0..params_node.child_count() {
                if let Some(child) = params_node.child(i) {
                    if child.kind() == "identifier" {
                        params.push(get_node_text(&child, source).to_string());
                    }
                }
            }
        }
        params
    }

    /// Count occurrences of `word` in `text` with word-boundary matching.
    fn count_word_occurrences(text: &str, word: &str) -> usize {
        let mut count = 0;
        let word_bytes = word.as_bytes();
        let text_bytes = text.as_bytes();
        let word_len = word_bytes.len();

        if word_len == 0 || text_bytes.len() < word_len {
            return 0;
        }

        for i in 0..=(text_bytes.len() - word_len) {
            if &text_bytes[i..i + word_len] == word_bytes {
                let before_ok = i == 0 || {
                    let b = text_bytes[i - 1];
                    !b.is_ascii_alphanumeric() && b != b'_'
                };
                let after_ok = i + word_len >= text_bytes.len() || {
                    let a = text_bytes[i + word_len];
                    !a.is_ascii_alphanumeric() && a != b'_'
                };
                if before_ok && after_ok {
                    count += 1;
                }
            }
        }
        count
    }
}
