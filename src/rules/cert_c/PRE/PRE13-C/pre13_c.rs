//! PRE13-C: Use the Standard predefined macros to test for versions and features
//!
//! This rule ensures that standard predefined macros are tested with `defined()` before
//! their values are used in preprocessor conditionals. Testing macro values without first
//! confirming they are defined can cause undefined behavior on non-conforming implementations.
//!
//! ## Non-compliant example:
//!
//! ```c
//! #if (__STDC__ == 1)  // Wrong: tests value without checking if defined
//!     // ...
//! #endif
//!
//! #if __STDC_VERSION__ >= 201112L  // Wrong: tests value without defined() check
//!     // ...
//! #endif
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! #if defined(__STDC__)
//!     #if (__STDC__ == 1)  // OK: first checked if defined
//!         // ...
//!     #endif
//! #endif
//!
//! #if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)  // OK: uses defined()
//!     // ...
//! #endif
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use std::rc::Rc;
use tree_sitter::Node;

pub struct Pre13C;

impl Pre13C {
    pub fn new() -> Self {
        Self
    }

    /// Standard predefined macros that should be tested with defined()
    #[allow(dead_code)]
    fn is_standard_macro(&self, name: &str) -> bool {
        matches!(
            name,
            "__STDC__"
                | "__STDC_VERSION__"
                | "__STDC_HOSTED__"
                | "__STDC_MB_MIGHT_NEQ_WC__"
                | "__STDC_UTF_16__"
                | "__STDC_UTF_32__"
                | "__STDC_ANALYZABLE__"
                | "__STDC_IEC_559__"
                | "__STDC_IEC_559_COMPLEX__"
                | "__STDC_ISO_10646__"
                | "__STDC_LIB_EXT1__"
                | "__STDC_NO_ATOMICS__"
                | "__STDC_NO_COMPLEX__"
                | "__STDC_NO_THREADS__"
                | "__STDC_NO_VLA__"
                | "__DATE__"
                | "__FILE__"
                | "__LINE__"
                | "__TIME__"
        )
    }

    /// Check if a preprocessor conditional uses standard macros without defined()
    fn check_preprocessor_conditional(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        defined_macros: &[String],
    ) {
        // Check both #if and #elif directives
        let is_conditional = node.kind() == "preproc_if" || node.kind() == "preproc_elif";
        if !is_conditional {
            return;
        }

        // Get the condition node
        let condition = match node.child_by_field_name("condition") {
            Some(c) => c,
            None => return,
        };

        // Get the condition text
        let condition_text = get_node_text(&condition, source);

        // Check if condition uses standard macros directly without defined()
        for macro_name in self.get_standard_macros() {
            // Check if the macro is used in the condition
            if condition_text.contains(macro_name) {
                // Check if it's used with defined() in THIS condition
                let defined_pattern = format!("defined({})", macro_name);
                let defined_pattern_spaces = format!("defined ({})", macro_name);

                if condition_text.contains(&defined_pattern)
                    || condition_text.contains(&defined_pattern_spaces)
                {
                    // Has defined() check in this condition - OK
                    continue;
                }

                // Check if it was checked with defined() in an enclosing #if
                if defined_macros.contains(&macro_name.to_string()) {
                    // Already checked in enclosing scope - OK
                    continue;
                }

                // This is a violation: using macro value without checking if it's defined
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Standard macro '{}' is used in preprocessor conditional without first checking if it is defined. Use 'defined({})' before testing its value.",
                        macro_name, macro_name
                    ),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(format!(
                        "Wrap the condition with 'defined({})' check: '#if defined({}) && ({})'",
                        macro_name, macro_name, condition_text
                    )),
                    ..Default::default()
                });

                // Only report once per condition, even if multiple macros are used incorrectly
                return;
            }
        }
    }
}

impl CertRule for Pre13C {
    fn rule_id(&self) -> &'static str {
        "PRE13-C"
    }

    fn description(&self) -> &'static str {
        "Use the Standard predefined macros to test for versions and features"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "PRE13-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let defined_macros: Vec<String> = Vec::new();
        self.check_node(node, source, &mut violations, &defined_macros);
        violations
    }
}

impl Pre13C {
    /// Walk the tree, threading a per-path `defined_macros` accumulator down
    /// `preproc_if` branches (each nested `#if defined(X)` extends the set
    /// for its own subtree only).
    ///
    /// Uses an explicit stack instead of recursion: this walks every node in
    /// the tree, so a deeply nested `#if`/`#elif` chain (or just deeply
    /// nested code in general) would cost one native call frame per level
    /// -- the same hostap-style risk class as the original ARR00-C/MEM33-C
    /// bug (task 153). `defined_macros` is read-only once built for a given
    /// subtree (only ever appended-to when entering a new `preproc_if`, never
    /// mutated in place or merged back), so an `Rc<Vec<String>>` shared
    /// handle reproduces the original borrowed-slice-vs-forked-clone
    /// behavior exactly: plain nodes pass the same `Rc` through to their
    /// children (cheap pointer clone, like the original `&[String]`
    /// reborrow), while `preproc_if` builds a new `Rc` for its children.
    fn check_node(
        &self,
        root: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        initial_defined_macros: &[String],
    ) {
        let mut stack: Vec<(Node, Rc<Vec<String>>)> =
            vec![(*root, Rc::new(initial_defined_macros.to_vec()))];

        while let Some((node, defined_macros)) = stack.pop() {
            // Check this node
            self.check_preprocessor_conditional(&node, source, violations, &defined_macros);

            // For preproc_if nodes, extract macros checked with defined() and pass to children
            if node.kind() == "preproc_if" {
                if let Some(condition) = node.child_by_field_name("condition") {
                    let condition_text = get_node_text(&condition, source);
                    let mut new_defined_macros = (*defined_macros).clone();

                    // Extract macros checked with defined() in this condition
                    for macro_name in self.get_standard_macros() {
                        let defined_pattern = format!("defined({})", macro_name);
                        let defined_pattern_spaces = format!("defined ({})", macro_name);
                        if condition_text.contains(&defined_pattern)
                            || condition_text.contains(&defined_pattern_spaces)
                        {
                            if !new_defined_macros.contains(&macro_name.to_string()) {
                                new_defined_macros.push(macro_name.to_string());
                            }
                        }
                    }

                    // Queue children with updated defined_macros set, in
                    // reverse so they're popped in original document order.
                    let new_macros = Rc::new(new_defined_macros);
                    for i in (0..node.child_count()).rev() {
                        if let Some(child) = node.child(i) {
                            stack.push((child, Rc::clone(&new_macros)));
                        }
                    }
                    continue;
                }
            }

            // Queue child nodes with the current defined_macros set
            for i in (0..node.child_count()).rev() {
                if let Some(child) = node.child(i) {
                    stack.push((child, Rc::clone(&defined_macros)));
                }
            }
        }
    }

    /// List of standard macros that need defined() checks
    fn get_standard_macros(&self) -> &[&str] {
        &[
            "__STDC__",
            "__STDC_VERSION__",
            "__STDC_HOSTED__",
            "__STDC_MB_MIGHT_NEQ_WC__",
            "__STDC_UTF_16__",
            "__STDC_UTF_32__",
            "__STDC_ANALYZABLE__",
            "__STDC_IEC_559__",
            "__STDC_IEC_559_COMPLEX__",
            "__STDC_ISO_10646__",
            "__STDC_LIB_EXT1__",
            "__STDC_NO_ATOMICS__",
            "__STDC_NO_COMPLEX__",
            "__STDC_NO_THREADS__",
            "__STDC_NO_VLA__",
        ]
    }
}
