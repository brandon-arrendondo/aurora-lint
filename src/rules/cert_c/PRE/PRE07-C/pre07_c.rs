use crate::manifest::{RuleCategory, Severity};
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use tree_sitter::Node;

pub struct PRE07C;

impl CertRule for PRE07C {
    fn rule_id(&self) -> &'static str {
        "PRE07-C"
    }

    fn cert_id(&self) -> &'static str {
        "PRE07"
    }

    fn description(&self) -> &'static str {
        "Avoid using repeated question marks in C source code"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn check(&self, _node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Trigraph sequences: ??= ??/ ??' ??( ??) ??! ??< ??> ??-
        // These are replaced by the preprocessor with: # \ ^ [ ] | { } ~
        let trigraph_chars = ['=', '/', '\'', '(', ')', '!', '<', '>', '-'];

        // Search source for trigraph patterns
        let lines: Vec<&str> = source.lines().collect();

        let mut in_block_comment = false;

        for (line_idx, line) in lines.iter().enumerate() {
            // Work with bytes to avoid UTF-8 issues
            let line_bytes = line.as_bytes();

            // Find where a line comment starts (// not inside a string)
            let line_comment_start = Self::find_line_comment_start(line_bytes);

            let mut i = 0;
            while i + 2 < line_bytes.len() {
                // Track block comment state
                if !in_block_comment
                    && i + 1 < line_bytes.len()
                    && line_bytes[i] == b'/'
                    && line_bytes[i + 1] == b'*'
                {
                    in_block_comment = true;
                    i += 2;
                    continue;
                }
                if in_block_comment
                    && i + 1 < line_bytes.len()
                    && line_bytes[i] == b'*'
                    && line_bytes[i + 1] == b'/'
                {
                    in_block_comment = false;
                    i += 2;
                    continue;
                }

                // Determine if we are currently inside a comment.
                let in_line_comment = line_comment_start.map(|lc| i >= lc).unwrap_or(false);
                let in_any_comment = in_block_comment || in_line_comment;

                // Inside a comment, only flag `??/` (which expands to `\` and can
                // accidentally extend a `//` comment onto the next line).
                // All other trigraphs in comments have no semantic effect in C99+.
                if in_any_comment
                    && i + 2 < line_bytes.len()
                    && line_bytes[i] == b'?'
                    && line_bytes[i + 1] == b'?'
                {
                    let third_char = line_bytes[i + 2] as char;
                    if trigraph_chars.contains(&third_char) && third_char == '/' {
                        // `??/` in comment: flag it (line-continuation danger)
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            file_path: String::new(),
                            message: "Trigraph sequence '??/' inside a comment expands to '\\' (line continuation), potentially including the next line in the comment.".to_string(),
                            line: line_idx + 1,
                            column: i + 1,
                            severity: self.severity(),
                            suggestion: Some("Avoid trigraphs by using alternative syntax or escaping the question marks".to_string()),
                            requires_manual_review: Some(false),
                        });
                    }
                    i += 1;
                    continue;
                }
                if in_any_comment {
                    i += 1;
                    continue;
                }

                // Check for ?? followed by trigraph character
                if line_bytes[i] == b'?' && line_bytes[i + 1] == b'?' {
                    let third_char = line_bytes[i + 2] as char;
                    if trigraph_chars.contains(&third_char) {
                        // Check if this is escaped by string splitting (like "?" "?!")
                        let mut is_escaped = false;
                        if i >= 2 && i + 3 < line_bytes.len() {
                            if line_bytes[i - 1] == b'?'
                                && line_bytes[i - 2] == b'"'
                                && line_bytes[i + 3] == b'"'
                            {
                                is_escaped = true;
                            }
                        }

                        if !is_escaped {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                file_path: String::new(),
                                message: format!(
                                    "Trigraph sequence '??{}' detected. Trigraphs can cause unintended behavior and are deprecated.",
                                    third_char
                                ),
                                line: line_idx + 1,
                                column: i + 1,
                                severity: self.severity(),
                                suggestion: Some("Avoid trigraphs by using alternative syntax or escaping the question marks".to_string()),
                                requires_manual_review: Some(false),
                            });
                        }
                    }
                }
                i += 1;
            }
        }

        violations
    }
}

impl PRE07C {
    /// Returns the byte offset where a `//` line comment starts, or None.
    /// Skips `//` inside string literals to avoid false-positive comment detection.
    fn find_line_comment_start(line: &[u8]) -> Option<usize> {
        let mut in_string = false;
        let mut in_char = false;
        let mut escaped = false;
        let mut i = 0;
        while i + 1 < line.len() {
            if escaped {
                escaped = false;
                i += 1;
                continue;
            }
            if line[i] == b'\\' {
                escaped = true;
                i += 1;
                continue;
            }
            if line[i] == b'"' && !in_char {
                in_string = !in_string;
            } else if line[i] == b'\'' && !in_string {
                in_char = !in_char;
            } else if !in_string && !in_char && line[i] == b'/' && line[i + 1] == b'/' {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}
