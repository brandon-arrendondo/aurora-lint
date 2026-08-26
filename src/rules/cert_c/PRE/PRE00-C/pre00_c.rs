use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

/// Find the byte offset of the first word-boundary match of `needle`
/// within `haystack`, or `None` if absent.
fn find_word(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let n = needle.len();
    if n == 0 || haystack.len() < n {
        return None;
    }
    for i in 0..=(haystack.len() - n) {
        if &haystack[i..i + n] == needle {
            let before_ok = i == 0 || {
                let b = haystack[i - 1];
                !b.is_ascii_alphanumeric() && b != b'_'
            };
            let after_ok = i + n >= haystack.len() || {
                let a = haystack[i + n];
                !a.is_ascii_alphanumeric() && a != b'_'
            };
            if before_ok && after_ok {
                return Some(i);
            }
        }
    }
    None
}

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

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(root, source, violations);
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

        // Multi-evaluation: any parameter used more than once, ignoring
        // references inside sizeof(...)/typeof(...)/__builtin_types_compatible_p(...)
        // argument lists -- those operands are never evaluated at runtime
        // (a compile-time-only read, not a second "evaluation" in the sense
        // PRE00-C cares about), unlike a real repeated use in a comparison,
        // arithmetic expression, or function-call argument. This is the
        // idiom curl's typecheck-gcc.h helper macros use throughout (e.g.
        // `curlcheck_long`/`curlcheck_ptr`: every repeated reference to
        // `expr` sits inside `__typeof__(expr)`).
        let safe_spans = Self::type_only_context_spans(&body);
        let params = Self::extract_macro_params(node, source);
        for param in &params {
            if Self::count_word_occurrences_outside_spans(&body, param, &safe_spans) > 1 {
                return true;
            }
        }
        false
    }

    /// Byte-offset spans (start, end) of the argument list of every
    /// `sizeof(...)`, `typeof(...)`/`__typeof__(...)`, and
    /// `__builtin_types_compatible_p(...)` call in `body`. A parameter
    /// reference entirely within one of these spans is not a runtime
    /// evaluation.
    fn type_only_context_spans(body: &str) -> Vec<(usize, usize)> {
        const KEYWORDS: &[&str] = &[
            "sizeof",
            "typeof",
            "__typeof__",
            "__typeof",
            "__builtin_types_compatible_p",
        ];
        let bytes = body.as_bytes();
        let mut spans = Vec::new();

        for &kw in KEYWORDS {
            let kw_bytes = kw.as_bytes();
            let mut i = 0;
            while let Some(rel) = find_word(&bytes[i..], kw_bytes) {
                let kw_start = i + rel;
                let mut j = kw_start + kw_bytes.len();
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b'(' {
                    let open = j;
                    let mut depth = 1i32;
                    let mut k = open + 1;
                    while k < bytes.len() && depth > 0 {
                        match bytes[k] {
                            b'(' => depth += 1,
                            b')' => depth -= 1,
                            _ => {}
                        }
                        k += 1;
                    }
                    // k is now one past the matching ')' (or end of body if
                    // unbalanced, which a real macro body never is).
                    spans.push((open + 1, k.saturating_sub(1)));
                }
                i = kw_start + kw_bytes.len();
            }
        }
        spans
    }

    /// Like `count_word_occurrences`, but ignores any occurrence whose
    /// start byte falls inside one of `safe_spans`.
    fn count_word_occurrences_outside_spans(
        text: &str,
        word: &str,
        safe_spans: &[(usize, usize)],
    ) -> usize {
        let word_bytes = word.as_bytes();
        let text_bytes = text.as_bytes();
        let word_len = word_bytes.len();

        if word_len == 0 || text_bytes.len() < word_len {
            return 0;
        }

        let mut count = 0;
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
                if before_ok && after_ok && !safe_spans.iter().any(|&(s, e)| i >= s && i < e) {
                    count += 1;
                }
            }
        }
        count
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
}
