// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

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
use crate::analyze::context::ProjectContext;
use crate::analyze::noreturn::{called_function_name, library_function_replaced};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::path::PathBuf;
use tree_sitter::Node;

/// The standard library function this rule reports.
const RAND: &str = "rand";

pub struct Msc30C {
    /// The prescan's macro tables: a project macro named `rand` replaces the
    /// library function in the files that can see it.
    project: RefCell<Option<ProjectContext>>,
    /// The file being checked, for the headers it includes.
    file_path: RefCell<Option<PathBuf>>,
}

impl Msc30C {
    pub fn new() -> Self {
        Self {
            project: RefCell::new(None),
            file_path: RefCell::new(None),
        }
    }

    /// Whether `rand` names something other than the library function
    /// anywhere in this file: see [`library_function_replaced`].
    fn rand_is_redefined(&self, root: &Node, source: &str) -> bool {
        library_function_replaced(
            root,
            source,
            RAND,
            self.project.borrow().as_ref(),
            self.file_path.borrow().as_deref(),
        )
    }

    /// Check if a function call is to rand()
    fn check_rand_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if called_function_name(node, source).as_deref() == Some(RAND) {
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

impl Default for Msc30C {
    fn default() -> Self {
        Self::new()
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

    fn cert_id(&self) -> &'static str {
        "MSC30-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.clone());
    }

    fn set_file_path(&self, path: &std::path::Path) {
        *self.file_path.borrow_mut() = Some(path.to_path_buf());
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Msc30C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // The spelling first: resolving a callee walks its scopes.
        let calls: Vec<Node> = query::find_descendants_of_kind(*node, "call_expression")
            .into_iter()
            .filter(|call| {
                call.child_by_field_name("function").is_some_and(|f| {
                    get_node_text(&f, source)
                        .trim_matches(|c: char| c == '(' || c == ')' || c.is_whitespace())
                        == RAND
                })
            })
            .collect();
        if calls.is_empty() || self.rand_is_redefined(node, source) {
            return;
        }
        for call in calls {
            self.check_rand_call(&call, source, violations);
        }
    }
}
