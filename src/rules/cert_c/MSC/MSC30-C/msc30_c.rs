//! MSC30-C: Do not use the rand() function for generating pseudorandom numbers
//!
//! This rule addresses the use of the C Standard library's rand() function,
//! which provides poor quality pseudorandom numbers that may be predictable.
//!
//! ## Non-compliant examples:
//!
//! **Using rand():**
//! ```c
//! #include <stdlib.h>
//! int main(void) {
//!     int random_number = rand();  // Violation: rand() produces poor quality random numbers
//!     return 0;
//! }
//! ```
//!
//! ## Compliant solutions:
//!
//! **POSIX systems - Use random():**
//! ```c
//! #include <stdlib.h>
//! int main(void) {
//!     long random_number = random();  // Better quality than rand()
//!     return 0;
//! }
//! ```
//!
//! **POSIX systems - Use drand48():**
//! ```c
//! #include <stdlib.h>
//! int main(void) {
//!     double random_number = drand48();  // Better quality than rand()
//!     return 0;
//! }
//! ```
//!
//! **For cryptographic purposes - Use arc4random():**
//! ```c
//! #include <stdlib.h>
//! int main(void) {
//!     uint32_t random_number = arc4random();  // Cryptographic quality
//!     return 0;
//! }
//! ```
//!
//! **Windows - Use BCryptGenRandom():**
//! ```c
//! #include <windows.h>
//! #include <bcrypt.h>
//! int main(void) {
//!     BYTE buffer[16];
//!     BCryptGenRandom(NULL, buffer, sizeof(buffer), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
//!     return 0;
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Msc30C;

impl Msc30C {
    pub fn new() -> Self {
        Self
    }

    /// Check if a function call is to rand()
    fn check_rand_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() == "call_expression" {
            if let Some(function_node) = node.child_by_field_name("function") {
                let function_name = get_node_text(&function_node, source);

                if function_name.trim() == "rand" {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: "Use of rand() function for pseudorandom number generation detected. rand() produces poor quality random numbers that may be predictable.".to_string(),
                        file_path: String::new(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        suggestion: Some(
                            "Replace rand() with a better alternative: random() (POSIX), drand48() (POSIX), arc4random() (cryptographic), or BCryptGenRandom() (Windows)".to_string()
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }
}

impl CertRule for Msc30C {
    fn rule_id(&self) -> &'static str {
        "MSC30-C"
    }

    fn description(&self) -> &'static str {
        "Do not use the rand() function for generating pseudorandom numbers"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MSC30-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Msc30C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for rand() calls
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_rand_call(&call, source, violations);
        }
    }
}
