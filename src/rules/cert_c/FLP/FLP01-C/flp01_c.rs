// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! FLP01-C: Take care in rearranging floating-point expressions
//!
//! This rule cautions against reorganizing floating-point expressions without accounting
//! for precision limitations. The C Standard (ISO/IEC 9899:2011, §5.1.2.3, ¶14) states:
//! "The implementation cannot generally apply the mathematical associative rules for
//! addition or multiplication, nor the distributive rule, because of roundoff error."
//!
//! ## Examples:
//!
//! **Problematic patterns:**
//! ```c
//! // These transformations may affect precision:
//! x * y * z        // vs. x *= y * z
//! (x - y) + y      // May not equal x due to rounding
//! x + x * y        // vs. x * (1.0 + y)
//! x * 0.2          // vs. x / 5.0
//! ```
//!
//! ## Detection Strategy:
//!
//! This rule is marked as **"unenforceable"** through automated detection alone in the
//! CERT C coding standard. Static analysis cannot reliably determine:
//! - Whether an expression was intentionally reorganized
//! - Whether the reorganization affects required precision
//! - What the original expression structure was
//!
//! Therefore, this implementation provides a **conservative stub** that:
//! - Does not report false positives
//! - Serves as a placeholder for potential future heuristics
//! - Documents the rule's requirements for manual code review
//!
//! **Manual review is recommended** for code involving floating-point arithmetic,
//! particularly in performance-critical sections or when compiler optimizations
//! (e.g., `-ffast-math`) are enabled.

use crate::manifest::{RuleCategory, Severity};
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use tree_sitter::Node;

pub struct Flp01C;

impl CertRule for Flp01C {
    fn rule_id(&self) -> &'static str {
        "FLP01-C"
    }

    fn cert_id(&self) -> &'static str {
        "FLP01"
    }

    fn description(&self) -> &'static str {
        "Take care in rearranging floating-point expressions"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn check(&self, _node: &Node, _source: &str) -> Vec<RuleViolation> {
        // Conservative implementation: No automated detection
        //
        // Rationale:
        // - CERT marks this rule as "unenforceable" through automated analysis
        // - Cannot determine reorganization intent without historical context
        // - Potential patterns (e.g., x * 0.2 vs x / 5.0) may be intentional
        // - Compiler optimizations may introduce valid reorganizations
        //
        // Recommendation:
        // - Enable compiler warnings for floating-point precision issues
        // - Review floating-point code manually during code reviews
        // - Use `-ffp-contract=off` to prevent expression contraction if precision is critical
        // - Document intentional reorganizations with comments

        Vec::new()
    }
}
