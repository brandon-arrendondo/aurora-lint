// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! MSC39-C: Do not call va_arg() on a va_list that has an indeterminate value
//!
//! This rule addresses undefined behavior that occurs when a va_list is used after
//! being passed to a function that calls va_arg() on it. According to the C Standard
//! (7.16, paragraph 3), if a function invokes va_arg with a va_list parameter, the
//! representation of that va_list in the calling function becomes indeterminate.
//!
//! ## Non-compliant examples:
//!
//! **Function that modifies caller's va_list:**
//! ```c
//! int contains_zero(size_t count, va_list ap) {  // Takes va_list by value
//!     for (size_t i = 1; i < count; ++i) {
//!         if (va_arg(ap, double) == 0.0) {  // Modifies va_list
//!             return 1;
//!         }
//!     }
//!     return 0;
//! }
//!
//! int print_reciprocals(size_t count, ...) {
//!     va_list ap;
//!     va_start(ap, count);
//!
//!     if (contains_zero(count, ap)) {  // Passes va_list
//!         va_end(ap);
//!         return 1;
//!     }
//!
//!     // ap now has indeterminate value - undefined behavior!
//!     for (size_t i = 0; i < count; ++i) {
//!         printf("%f ", 1.0 / va_arg(ap, double));
//!     }
//!
//!     va_end(ap);
//!     return 0;
//! }
//! ```
//!
//! The finding is the caller's later `va_arg(ap, double)`, not the callee:
//! passing a `va_list` by value to a function that calls `va_arg` on it is
//! permitted, and the caller may still call `va_end`. That caller-side
//! form is not implemented yet, so this rule reports nothing for now. It no
//! longer reports the callee's by-value parameter.
//!
//! ## Compliant solutions:
//!
//! **Use va_list pointer and va_copy:**
//! ```c
//! int contains_zero(size_t count, va_list *ap) {  // Takes pointer
//!     va_list ap1;
//!     va_copy(ap1, *ap);  // Create a copy
//!     for (size_t i = 1; i < count; ++i) {
//!         if (va_arg(ap1, double) == 0.0) {
//!             va_end(ap1);
//!             return 1;
//!         }
//!     }
//!     va_end(ap1);
//!     return 0;
//! }
//!
//! int print_reciprocals(size_t count, ...) {
//!     va_list ap;
//!     va_start(ap, count);
//!
//!     if (contains_zero(count, &ap)) {  // Pass address
//!         va_end(ap);
//!         return 1;
//!     }
//!
//!     // ap still has determinate value - safe!
//!     for (size_t i = 0; i < count; ++i) {
//!         printf("%f ", 1.0 / va_arg(ap, double));
//!     }
//!
//!     va_end(ap);
//!     return 0;
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use tree_sitter::Node;

pub struct Msc39C;

impl Msc39C {
    pub fn new() -> Self {
        Self
    }
}

impl CertRule for Msc39C {
    fn rule_id(&self) -> &'static str {
        "MSC39-C"
    }

    fn description(&self) -> &'static str {
        "Do not call va_arg() on a va_list that has an indeterminate value"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "MSC39-C"
    }

    fn scan(&self, _node: &Node, _source: &str, _violations: &mut Vec<RuleViolation>) {}
}
