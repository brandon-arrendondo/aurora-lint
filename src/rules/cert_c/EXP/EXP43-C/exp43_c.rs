//! EXP43-C: Avoid undefined behavior when using restrict-qualified pointers
//!
//! Restrict-qualified pointers must not alias each other. Assigning one restrict
//! pointer to another or passing overlapping memory to restrict parameters causes UB.
//!
//! ## Violations detected:
//! 1. Assigning one restrict pointer to another
//! 2. Initializing a restrict pointer from another restrict pointer
//! 3. Passing same array/pointer multiple times to restrict parameters
//! 4. Passing overlapping memory regions to restrict parameters (memcpy overlap)

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Exp43C;

impl CertRule for Exp43C {
    fn rule_id(&self) -> &'static str {
        "EXP43-C"
    }

    fn description(&self) -> &'static str {
        "Avoid undefined behavior when using restrict-qualified pointers"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP43-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // restrict_vars and pointer_bases must be scoped per function: a local
        // pointer named "p" in one function is a completely different object
        // than a same-named local "p" in another function, and resolving
        // aliasing bases through a whole-translation-unit map lets an
        // assignment in one function silently pollute the alias resolution of
        // an unrelated call in a different function (e.g. `p = w;` in `f`
        // making `strcpy(p, w)` in an unrelated `g(char *p, char *w)` look
        // aliased). Mirrors the per-function reset pattern used by EXP39-C.
        let functions = query::find_descendants_of_kind(*node, "function_definition");

        if functions.is_empty() {
            // No functions at all (e.g. a header-only or declarations-only
            // snippet) - fall back to treating the whole translation unit as
            // a single scope, matching pre-fix behavior for this edge case.
            self.check_scope(
                node,
                source,
                &HashSet::new(),
                &HashMap::new(),
                &mut violations,
            );
        } else {
            // File-scope (translation-unit-level, outside any function body)
            // restrict declarations are genuinely shared by every function
            // that references them (e.g. `int *restrict a; int *restrict b;`
            // at file scope, aliased inside `main`), so seed every function's
            // scope with this file-scope-only base. Collected from direct
            // children of the translation unit only, so it never reaches
            // into a function body and re-introduces the per-function
            // conflation this fix removes.
            let mut global_restrict_vars: HashSet<String> = HashSet::new();
            let mut global_pointer_bases: HashMap<String, String> = HashMap::new();
            self.collect_top_level_restrict(
                node,
                source,
                &mut global_restrict_vars,
                &mut global_pointer_bases,
            );

            for func in &functions {
                self.check_scope(
                    func,
                    source,
                    &global_restrict_vars,
                    &global_pointer_bases,
                    &mut violations,
                );
            }
        }

        violations
    }
}

impl Exp43C {
    /// Collect restrict-qualified declarations and pointer-base assignments
    /// that are direct children of the translation unit (i.e. file scope,
    /// not inside any function body). These are shared across every
    /// function, unlike function-local declarations which must stay scoped
    /// per-function (see `check`).
    fn collect_top_level_restrict(
        &self,
        node: &Node,
        source: &str,
        restrict_vars: &mut HashSet<String>,
        pointer_bases: &mut HashMap<String, String>,
    ) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "declaration" => {
                        let decl_text = get_node_text(&child, source);
                        if decl_text.contains("restrict") {
                            if let Some(var_name) = self.extract_var_name(&child, source) {
                                restrict_vars.insert(var_name);
                            }
                        }
                    }
                    "assignment_expression" => {
                        if let (Some(left), Some(right)) = (
                            child.child_by_field_name("left"),
                            child.child_by_field_name("right"),
                        ) {
                            let left_text = get_node_text(&left, source).to_string();
                            let right_text = get_node_text(&right, source);
                            let base = self.extract_base_pointer(right_text);
                            if !base.is_empty() {
                                pointer_bases.insert(left_text, base);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Run all three passes over a single scope (one function's body, or, as
    /// a fallback, the whole translation unit when there are no functions).
    /// `restrict_vars`/`pointer_bases` start from the given file-scope-only
    /// seed and are then extended with this scope's own declarations, so
    /// same-named locals in different functions never get conflated with
    /// each other (only genuinely file-scope declarations are shared).
    fn check_scope(
        &self,
        scope_node: &Node,
        source: &str,
        seed_restrict_vars: &HashSet<String>,
        seed_pointer_bases: &HashMap<String, String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let mut restrict_vars: HashSet<String> = seed_restrict_vars.clone();
        let mut pointer_bases: HashMap<String, String> = seed_pointer_bases.clone();

        // First pass: find restrict pointer declarations and track pointer bases
        self.find_restrict_declarations(scope_node, source, &mut restrict_vars, &mut pointer_bases);

        // Second pass: find assignments/initializations between restrict pointers
        self.find_restrict_violations(scope_node, source, &restrict_vars, violations);

        // Third pass: find function calls with potentially overlapping restrict params
        self.find_overlapping_restrict_calls(scope_node, source, &pointer_bases, violations);
    }

    /// Find restrict-qualified pointer declarations and track pointer bases
    fn find_restrict_declarations(
        &self,
        node: &Node,
        source: &str,
        restrict_vars: &mut HashSet<String>,
        pointer_bases: &mut HashMap<String, String>,
    ) {
        for n in query::find_descendants_of_kinds(
            *node,
            &["declaration", "assignment_expression", "init_declarator"],
        ) {
            if n.kind() == "declaration" {
                let decl_text = get_node_text(&n, source);
                if decl_text.contains("restrict") {
                    // Extract variable name
                    if let Some(var_name) = self.extract_var_name(&n, source) {
                        restrict_vars.insert(var_name);
                    }
                }
            }

            // Track pointer assignments like: ptr2 = ptr1 + 3
            if n.kind() == "assignment_expression" {
                if let (Some(left), Some(right)) = (
                    n.child_by_field_name("left"),
                    n.child_by_field_name("right"),
                ) {
                    let left_text = get_node_text(&left, source).to_string();
                    let right_text = get_node_text(&right, source);
                    // Extract base from expressions like "ptr1 + 3" or "c_str"
                    let base = self.extract_base_pointer(right_text);
                    if !base.is_empty() {
                        pointer_bases.insert(left_text, base);
                    }
                }
            }

            // Track init_declarator like: char *ptr2 = ptr1 + 3
            if n.kind() == "init_declarator" {
                if let (Some(declarator), Some(value)) = (
                    n.child_by_field_name("declarator"),
                    n.child_by_field_name("value"),
                ) {
                    if let Some(var_name) = self.find_identifier(&declarator, source) {
                        let value_text = get_node_text(&value, source);
                        let base = self.extract_base_pointer(value_text);
                        if !base.is_empty() {
                            pointer_bases.insert(var_name, base);
                        }
                    }
                }
            }
        }
    }

    /// Extract base pointer from expression like "ptr + 3" -> "ptr"
    fn extract_base_pointer(&self, expr: &str) -> String {
        let trimmed = expr.trim();
        // Handle expressions like "ptr1 + 3" or "c_str"
        if trimmed.contains('+') || trimmed.contains('-') {
            trimmed
                .split(['+', '-'])
                .next()
                .unwrap_or("")
                .trim()
                .to_string()
        } else {
            trimmed.to_string()
        }
    }

    /// Find assignments/initializations between restrict pointers
    fn find_restrict_violations(
        &self,
        node: &Node,
        source: &str,
        restrict_vars: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in
            query::find_descendants_of_kinds(*node, &["assignment_expression", "init_declarator"])
        {
            // Check assignment expressions: a = b
            if n.kind() == "assignment_expression" {
                if let (Some(left), Some(right)) = (
                    n.child_by_field_name("left"),
                    n.child_by_field_name("right"),
                ) {
                    let left_text = get_node_text(&left, source);
                    let right_text = get_node_text(&right, source);

                    // Check if both sides are restrict-qualified variables
                    if restrict_vars.contains(left_text) && restrict_vars.contains(right_text) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: format!(
                                "Assignment from restrict pointer '{}' to restrict pointer '{}'. \
                                 This causes undefined behavior due to pointer aliasing.",
                                right_text, left_text
                            ),
                            severity: self.severity(),
                            line: n.start_position().row + 1,
                            column: n.start_position().column + 1,
                            file_path: String::new(),
                            suggestion: Some(
                                "Use non-restrict pointers for aliased references".to_string(),
                            ),
                            requires_manual_review: None,
                        });
                    }
                }
            }

            // Check init_declarator: int *restrict p2 = p1
            if n.kind() == "init_declarator" {
                // Check if parent declaration has restrict
                let parent_text = if let Some(parent) = n.parent() {
                    get_node_text(&parent, source)
                } else {
                    ""
                };

                if parent_text.contains("restrict") {
                    if let Some(value) = n.child_by_field_name("value") {
                        let value_text = get_node_text(&value, source);
                        // If initializing from another restrict pointer
                        if restrict_vars.contains(value_text) {
                            // Check if this is inside an inner block (compound_statement)
                            // Inner block scope allows restrict aliasing
                            if !self.is_in_inner_block(&n) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    message: format!(
                                        "Initializing restrict pointer from another restrict pointer '{}'. \
                                         This causes undefined behavior due to pointer aliasing.",
                                        value_text
                                    ),
                                    severity: self.severity(),
                                    line: n.start_position().row + 1,
                                    column: n.start_position().column + 1,
                                    file_path: String::new(),
                                    suggestion: Some(
                                        "Use non-restrict pointers for aliased references".to_string(),
                                    ),
                                    requires_manual_review: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check if node is inside an inner block (compound_statement within compound_statement)
    fn is_in_inner_block(&self, node: &Node) -> bool {
        let mut compound_count = 0;
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "compound_statement" {
                compound_count += 1;
                if compound_count >= 2 {
                    return true;
                }
            }
            current = parent.parent();
        }
        false
    }

    /// Find function calls with potentially overlapping restrict parameters
    fn find_overlapping_restrict_calls(
        &self,
        node: &Node,
        source: &str,
        pointer_bases: &HashMap<String, String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if let Some(args) = node.child_by_field_name("arguments") {
                    // Collect all argument expressions
                    let arg_exprs: Vec<String> = self.collect_arg_expressions(&args, source);

                    // Special case: memcpy with aliased pointers (overlapping memory)
                    // memcpy has restrict parameters, so overlapping is UB
                    if func_name == "memcpy" && arg_exprs.len() >= 2 {
                        // For memcpy, check if both args derive from same ultimate base
                        // ANY aliasing is a problem because we can't prove non-overlap
                        let base0 = self.extract_base_pointer(&arg_exprs[0]);
                        let base1 = self.extract_base_pointer(&arg_exprs[1]);
                        let resolved0 = self.resolve_pointer_base(&base0, pointer_bases);
                        let resolved1 = self.resolve_pointer_base(&base1, pointer_bases);

                        if resolved0 == resolved1 && !resolved0.is_empty() {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                message: format!(
                                    "memcpy called with potentially overlapping memory regions (both derive from '{}'). \
                                     memcpy's restrict parameters require non-overlapping memory.",
                                    resolved0
                                ),
                                severity: self.severity(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                file_path: String::new(),
                                suggestion: Some(
                                    "Use memmove for overlapping memory regions".to_string(),
                                ),
                                requires_manual_review: None,
                            });
                            return;
                        }
                    }

                    // Check for same argument appearing multiple times
                    // Distinguish between:
                    // - f(a, b, b) - b duplicated in positions 2,3 (likely const restrict - OK)
                    // - f(a, a, a) - a appears in position 1 AND other positions (likely write+read - UB)
                    if self.has_output_aliased_with_input(&arg_exprs) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: format!(
                                "Function '{}' called with same pointer for output and input parameters. \
                                 If output parameter is non-const restrict, this causes undefined behavior.",
                                func_name
                            ),
                            severity: self.severity(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            file_path: String::new(),
                            suggestion: Some(
                                "Ensure output restrict parameter receives a unique pointer".to_string(),
                            ),
                            requires_manual_review: None,
                        });
                        return;
                    }

                    // Check for overlapping memory regions (via pointer aliasing)
                    // Only flag for known standard library functions with non-const restrict params
                    // For user-defined functions, we can't know if params are const restrict
                    let known_restrict_funcs = [
                        "strcpy", "strncpy", "strcat", "strncat", "sprintf", "snprintf",
                    ];
                    if known_restrict_funcs.contains(&func_name)
                        && self.has_aliased_args(&arg_exprs, pointer_bases)
                    {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: format!(
                                "Function '{}' called with aliased pointers. \
                                 If parameters are restrict-qualified, overlapping memory causes undefined behavior.",
                                func_name
                            ),
                            severity: self.severity(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            file_path: String::new(),
                            suggestion: Some(
                                "Ensure memory regions do not overlap when using restrict pointers".to_string(),
                            ),
                            requires_manual_review: None,
                        });
                        return;
                    }

                    // Check for overlapping base + offset patterns (but exclude non-overlapping)
                    if self.has_definitely_overlapping_args(&arg_exprs) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: format!(
                                "Function '{}' called with overlapping memory regions. \
                                 If parameters are restrict-qualified, this causes undefined behavior.",
                                func_name
                            ),
                            severity: self.severity(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            file_path: String::new(),
                            suggestion: Some(
                                "Ensure memory regions do not overlap when using restrict pointers".to_string(),
                            ),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }

        // Recurse
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.find_overlapping_restrict_calls(&child, source, pointer_bases, violations);
            }
        }
    }

    /// Check if the first pointer argument (output) is aliased with any subsequent argument (input)
    /// Pattern: f(n, out, in1, in2) - if out == in1 or out == in2, it's likely UB
    /// But f(n, out, in, in) where only inputs are same is often OK (const restrict)
    fn has_output_aliased_with_input(&self, args: &[String]) -> bool {
        // Find first non-numeric argument (likely the output pointer)
        let mut first_pointer_idx = None;
        let mut first_pointer = String::new();

        for (i, arg) in args.iter().enumerate() {
            let trimmed = arg.trim();
            // Skip numeric literals and sizeof expressions
            if trimmed.is_empty()
                || trimmed.chars().all(|c| c.is_ascii_digit())
                || trimmed.starts_with("sizeof")
            {
                continue;
            }
            first_pointer_idx = Some(i);
            first_pointer = trimmed.to_string();
            break;
        }

        // If we found a first pointer, check if it appears in later positions
        if let Some(idx) = first_pointer_idx {
            for arg in args.iter().skip(idx + 1) {
                let trimmed = arg.trim();
                if trimmed == first_pointer {
                    return true;
                }
            }
        }

        false
    }

    /// Collect argument expressions from argument_list
    fn collect_arg_expressions(&self, args: &Node, source: &str) -> Vec<String> {
        let mut result = Vec::new();
        for i in 0..args.child_count() {
            if let Some(child) = args.child(i) {
                let kind = child.kind();
                if kind != "(" && kind != ")" && kind != "," {
                    result.push(get_node_text(&child, source).to_string());
                }
            }
        }
        result
    }

    /// Check if same argument appears multiple times as IDENTICAL expressions
    /// (not just same base with different offsets)
    #[allow(dead_code)]
    fn has_duplicate_args(&self, args: &[String]) -> bool {
        let mut seen: HashSet<String> = HashSet::new();
        for arg in args {
            let trimmed = arg.trim().to_string();
            // Skip numeric literals and empty
            if trimmed.is_empty() || trimmed.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            // Only flag if EXACT same expression (e.g., "a, a, a" not "d+50, d")
            if seen.contains(&trimmed) {
                return true;
            }
            seen.insert(trimmed);
        }
        false
    }

    /// Recursively resolve pointer base through the pointer_bases chain
    fn resolve_pointer_base(&self, ptr: &str, pointer_bases: &HashMap<String, String>) -> String {
        let mut current = ptr.to_string();
        let mut visited = std::collections::HashSet::new();

        while let Some(base) = pointer_bases.get(&current) {
            if visited.contains(base) {
                break; // Avoid infinite loops
            }
            visited.insert(base.clone());
            current = base.clone();
        }
        current
    }

    /// Check if arguments are aliased (derived from same base) AND overlapping
    fn has_aliased_args(&self, args: &[String], pointer_bases: &HashMap<String, String>) -> bool {
        // Get base pointers and offsets for all arguments
        let arg_info: Vec<(String, i64)> = args
            .iter()
            .map(|arg| {
                let base = self.extract_base_pointer(arg);
                let offset = self.extract_offset(arg);
                // Recursively resolve through pointer chain: ptr2 -> ptr1 -> c_str
                let resolved_base = self.resolve_pointer_base(&base, pointer_bases);
                (resolved_base, offset)
            })
            .collect();

        // Check if any two arguments have same base AND are potentially overlapping
        for i in 0..arg_info.len() {
            for j in (i + 1)..arg_info.len() {
                let (base_i, offset_i) = &arg_info[i];
                let (base_j, offset_j) = &arg_info[j];

                if base_i.is_empty() || base_j.is_empty() {
                    continue;
                }

                // Skip if both are numeric literals
                if base_i.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }

                if base_i == base_j {
                    // Same base - check if offsets indicate overlap
                    // If offsets are far apart (>= 50), likely non-overlapping
                    let diff = (*offset_i - *offset_j).abs();
                    if diff < 50 {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check for definitely overlapping array arguments
    /// Returns true only if we can prove overlap (small offsets)
    fn has_definitely_overlapping_args(&self, args: &[String]) -> bool {
        // Look for patterns where same base is used with small offsets
        // e.g., (base, base + 3) - likely overlapping
        // but (base + 50, base) with n=50 - might not overlap
        for i in 0..args.len() {
            for j in (i + 1)..args.len() {
                let a = args[i].trim();
                let b = args[j].trim();

                let base_a = self.extract_base_pointer(a);
                let base_b = self.extract_base_pointer(b);

                if base_a == base_b && !base_a.is_empty() {
                    // Same base - check offsets
                    let offset_a = self.extract_offset(a);
                    let offset_b = self.extract_offset(b);

                    // If one is base and other is base + small_offset, likely overlap
                    if offset_a == 0 || offset_b == 0 {
                        let other_offset = offset_a.max(offset_b);
                        // Small offset (< 50) is likely overlapping with typical buffer operations
                        if other_offset > 0 && other_offset < 50 {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Extract numeric offset from expression like "ptr + 3" -> 3
    fn extract_offset(&self, expr: &str) -> i64 {
        let trimmed = expr.trim();
        if let Some(pos) = trimmed.find('+') {
            trimmed[pos + 1..].trim().parse().unwrap_or(0)
        } else if let Some(pos) = trimmed.find('-') {
            -trimmed[pos + 1..].trim().parse().unwrap_or(0)
        } else {
            0
        }
    }

    /// Extract variable name from declaration
    fn extract_var_name(&self, decl: &Node, source: &str) -> Option<String> {
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" || child.kind() == "pointer_declarator" {
                    return self.find_identifier(&child, source);
                }
                if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }

    /// Find identifier in node tree
    fn find_identifier(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = self.find_identifier(&child, source) {
                    return Some(name);
                }
            }
        }

        None
    }
}
