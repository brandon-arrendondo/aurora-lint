//! PRE04-C: Do not reuse a standard header file name
//!
//! This rule prevents creating user-defined header files that reuse names of
//! standard C library headers. Reusing standard header names can cause undefined
//! behavior and confusion where the wrong header file gets included during compilation.
//!
//! ## Non-compliant example:
//!
//! ```c
//! #include "stdio.h"  // Creates ambiguity with standard library
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! #include "mystdio.h"  // Unique name clarifies intent
//! ```
//!
//! ## Standard Headers (C11 - 29 headers):
//!
//! assert.h, ctype.h, errno.h, fenv.h, float.h, inttypes.h, iso646.h,
//! limits.h, locale.h, math.h, setjmp.h, signal.h, stdalign.h, stdarg.h,
//! stdatomic.h, stdbool.h, stddef.h, stdint.h, stdio.h, stdlib.h, string.h,
//! tgmath.h, threads.h, time.h, uchar.h, wchar.h, wctype.h, complex.h

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pre04C {
    standard_headers: Vec<&'static str>,
}

impl Pre04C {
    pub fn new() -> Self {
        Self {
            standard_headers: vec![
                "assert.h",
                "complex.h",
                "ctype.h",
                "errno.h",
                "fenv.h",
                "float.h",
                "inttypes.h",
                "iso646.h",
                "limits.h",
                "locale.h",
                "math.h",
                "setjmp.h",
                "signal.h",
                "stdalign.h",
                "stdarg.h",
                "stdatomic.h",
                "stdbool.h",
                "stddef.h",
                "stdint.h",
                "stdio.h",
                "stdlib.h",
                "string.h",
                "tgmath.h",
                "threads.h",
                "time.h",
                "uchar.h",
                "wchar.h",
                "wctype.h",
            ],
        }
    }

    /// Extract the header filename from an include directive
    fn extract_header_name(&self, node: &Node, source: &str) -> Option<String> {
        // Look for the path node which contains the string literal
        let path_node = node.child_by_field_name("path")?;
        let path_text = get_node_text(&path_node, source);

        // Remove surrounding quotes if present
        let trimmed = path_text.trim();
        if trimmed.starts_with('"') && trimmed.ends_with('"') {
            let filename = trimmed.trim_matches('"');
            return Some(filename.to_string());
        }

        None
    }

    /// Check if the header name matches a standard C library header
    fn is_standard_header(&self, header_name: &str) -> bool {
        self.standard_headers.contains(&header_name)
    }

    /// Check an include directive for reuse of standard header names
    fn check_include_directive(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() != "preproc_include" {
            return;
        }

        // Extract the header filename
        let header_name = match self.extract_header_name(node, source) {
            Some(name) => name,
            None => return,
        };

        // Check if it matches a standard header
        if self.is_standard_header(&header_name) {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: format!(
                    "User-defined header file '{}' reuses a standard C library header name. Use a unique name instead.",
                    header_name
                ),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some(format!(
                    "Rename the header file to a unique name (e.g., 'my{}')",
                    header_name
                )),
                ..Default::default()
            });
        }
    }
}

impl CertRule for Pre04C {
    fn rule_id(&self) -> &'static str {
        "PRE04-C"
    }

    fn description(&self) -> &'static str {
        "Do not reuse a standard header file name"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "PRE04-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for include_node in query::find_descendants_of_kind(*node, "preproc_include") {
            self.check_include_directive(&include_node, source, &mut violations);
        }
        violations
    }
}
