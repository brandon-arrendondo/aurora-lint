//! DCL02-C: Use visually distinct identifiers
//!
//! This rule detects identifiers that differ only by visually similar characters.
//! Such identifiers can lead to confusion and errors during code review and maintenance.
//!
//! VIOLATIONS:
//! - int id_O; int id_0;           // O (letter) vs 0 (digit)
//! - int var1; int varl;           // 1 (digit) vs l (lowercase L)
//! - int count_I; int count_l;     // I (uppercase i) vs l (lowercase L)
//! - int valS; int val5;           // S (letter) vs 5 (digit)
//! - int sumB; int sum8;           // B (letter) vs 8 (digit)
//! - int rn_value; int m_value;    // rn (two chars) vs m (one char)
//!
//! COMPLIANT:
//! - int id_a; int id_b;           // Clearly distinct identifiers
//! - int first; int second;        // Meaningful, distinct names
//! - int counter; int index;       // Different names entirely
//!
//! Visually similar character pairs:
//! - 0 (zero) ↔ O, Q, D (capital letters)
//! - 1 (one) ↔ I, l (capital i, lowercase L)
//! - 2 (two) ↔ Z (capital z)
//! - 5 (five) ↔ S (capital s)
//! - 8 (eight) ↔ B (capital b)
//! - n ↔ h (lowercase)
//! - m ↔ rn (lowercase m vs r+n sequence)

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Dcl02C;

impl CertRule for Dcl02C {
    fn rule_id(&self) -> &'static str {
        "DCL02-C"
    }

    fn description(&self) -> &'static str {
        "Use visually distinct identifiers"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL02-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Collect all identifiers in each scope (with depth limit to prevent stack overflow)
        let mut scope_analyzer = ScopeAnalyzer::new();
        scope_analyzer.analyze_scope_with_depth(node, source, &mut violations, 0);

        violations
    }
}

struct ScopeAnalyzer {
    // Map of normalized identifier -> list of (actual identifier, position)
    identifiers: HashMap<String, Vec<(String, usize, usize)>>,
}

impl ScopeAnalyzer {
    fn new() -> Self {
        Self {
            identifiers: HashMap::new(),
        }
    }

    #[allow(dead_code)]
    fn analyze_scope(&mut self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.analyze_scope_with_depth(node, source, violations, 0);
    }

    fn analyze_scope_with_depth(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        depth: usize,
    ) {
        // Limit scope nesting depth to prevent stack overflow
        const MAX_SCOPE_DEPTH: usize = 100;
        if depth > MAX_SCOPE_DEPTH {
            return;
        }

        // Use iterative traversal instead of recursion to avoid stack overflow
        self.collect_identifiers_iterative(node, source);

        // Check for visually similar identifiers
        self.check_visual_similarity(violations);

        // Analyze nested scopes (functions, blocks) iteratively
        self.analyze_child_scopes_iterative(node, source, violations, depth);
    }

    fn collect_identifiers_iterative(&mut self, root: &Node, source: &str) {
        // Use explicit stack instead of recursion to avoid stack overflow
        let root_id = root.id();
        let mut stack = vec![*root];

        while let Some(node) = stack.pop() {
            match node.kind() {
                "declaration" | "parameter_declaration" => {
                    if let Some(identifier) = self.extract_identifier(&node, source) {
                        let normalized = normalize_identifier(&identifier);
                        let pos = node.start_position();

                        self.identifiers.entry(normalized).or_default().push((
                            identifier,
                            pos.row + 1,
                            pos.column + 1,
                        ));
                    }
                }
                "function_definition" => {
                    // Extract function name
                    if let Some(declarator) = node.child_by_field_name("declarator") {
                        if let Some(func_name) = self.get_function_name(&declarator, source) {
                            let normalized = normalize_identifier(&func_name);
                            let pos = node.start_position();

                            self.identifiers.entry(normalized).or_default().push((
                                func_name,
                                pos.row + 1,
                                pos.column + 1,
                            ));
                        }
                    }
                    // Don't recurse into function body here - will be handled separately
                    continue;
                }
                _ => {
                    // Add children to the stack, but stop at any nested compound
                    // statement: each block is a separate lexical scope, collected and
                    // checked on its own by analyze_child_scopes_iterative. Folding a
                    // block's declarations into its ancestors would re-report the same
                    // block-local pair once per enclosing scope (task 220). The root
                    // node itself is the scope currently being collected, so always
                    // descend into it even when it is a compound statement.
                    let is_root = node.id() == root_id;
                    if is_root || node.kind() != "compound_statement" {
                        for i in (0..node.child_count()).rev() {
                            if let Some(child) = node.child(i) {
                                stack.push(child);
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_child_scopes_iterative(
        &mut self,
        root: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        depth: usize,
    ) {
        // Use an explicit stack instead of recursion to avoid stack overflow.
        // Seed it with the root's children, never the root itself: the root is the
        // scope already collected and checked by the caller. Re-pushing the root would
        // let a nested-block root re-match the compound_statement arm below and
        // re-analyze itself at depth+1 repeatedly (up to MAX_SCOPE_DEPTH), emitting the
        // same finding ~100 times (task 220).
        let mut stack: Vec<Node> = Vec::new();
        for i in (0..root.child_count()).rev() {
            if let Some(child) = root.child(i) {
                stack.push(child);
            }
        }

        while let Some(node) = stack.pop() {
            match node.kind() {
                "function_definition" => {
                    // Analyze function body as a new scope
                    if let Some(body) = node.child_by_field_name("body") {
                        let mut child_analyzer = ScopeAnalyzer::new();

                        // Include function parameters in the function scope
                        if let Some(declarator) = node.child_by_field_name("declarator") {
                            child_analyzer.collect_parameters(&declarator, source);
                        }

                        child_analyzer.analyze_scope_with_depth(
                            &body,
                            source,
                            violations,
                            depth + 1,
                        );
                    }
                }
                "compound_statement" if !self.is_function_body(&node) => {
                    // Analyze nested block as a new scope
                    let mut child_analyzer = ScopeAnalyzer::new();
                    child_analyzer.analyze_scope_with_depth(&node, source, violations, depth + 1);
                }
                _ => {
                    // Add children to stack to find nested scopes
                    for i in (0..node.child_count()).rev() {
                        if let Some(child) = node.child(i) {
                            stack.push(child);
                        }
                    }
                }
            }
        }
    }

    #[allow(dead_code)]
    fn collect_identifiers(&mut self, node: &Node, source: &str) {
        match node.kind() {
            "declaration" | "parameter_declaration" => {
                if let Some(identifier) = self.extract_identifier(node, source) {
                    let normalized = normalize_identifier(&identifier);
                    let pos = node.start_position();

                    self.identifiers.entry(normalized).or_default().push((
                        identifier,
                        pos.row + 1,
                        pos.column + 1,
                    ));
                }
            }
            "function_definition" => {
                // Extract function name
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    if let Some(func_name) = self.get_function_name(&declarator, source) {
                        let normalized = normalize_identifier(&func_name);
                        let pos = node.start_position();

                        self.identifiers.entry(normalized).or_default().push((
                            func_name,
                            pos.row + 1,
                            pos.column + 1,
                        ));
                    }
                }
                // Don't recurse into function body here - will be handled by analyze_child_scopes
            }
            _ => {
                // Recurse into children (except function bodies which are separate scopes)
                if node.kind() != "compound_statement" || !self.is_function_body(node) {
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            self.collect_identifiers(&child, source);
                        }
                    }
                }
            }
        }
    }

    #[allow(dead_code)]
    fn analyze_child_scopes(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        match node.kind() {
            "function_definition" => {
                // Analyze function body as a new scope
                if let Some(body) = node.child_by_field_name("body") {
                    let mut child_analyzer = ScopeAnalyzer::new();

                    // Include function parameters in the function scope
                    if let Some(declarator) = node.child_by_field_name("declarator") {
                        child_analyzer.collect_parameters(&declarator, source);
                    }

                    child_analyzer.analyze_scope(&body, source, violations);
                }
            }
            "compound_statement" if !self.is_function_body(node) => {
                // Analyze nested block as a new scope
                let mut child_analyzer = ScopeAnalyzer::new();
                child_analyzer.analyze_scope(node, source, violations);
            }
            _ => {
                // Recurse to find nested scopes
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        self.analyze_child_scopes(&child, source, violations);
                    }
                }
            }
        }
    }

    fn collect_parameters(&mut self, declarator: &Node, source: &str) {
        if let Some(params) = declarator.child_by_field_name("parameters") {
            for i in 0..params.child_count() {
                if let Some(param) = params.child(i) {
                    if param.kind() == "parameter_declaration" {
                        if let Some(identifier) = self.extract_identifier(&param, source) {
                            let normalized = normalize_identifier(&identifier);
                            let pos = param.start_position();

                            self.identifiers.entry(normalized).or_default().push((
                                identifier,
                                pos.row + 1,
                                pos.column + 1,
                            ));
                        }
                    }
                }
            }
        }
    }

    fn is_function_body(&self, node: &Node) -> bool {
        // Check if this compound_statement is a direct child of a function_definition
        if let Some(parent) = node.parent() {
            parent.kind() == "function_definition"
        } else {
            false
        }
    }

    fn extract_identifier(&self, node: &Node, source: &str) -> Option<String> {
        self.extract_identifier_with_depth(node, source, 0)
    }

    fn extract_identifier_with_depth(
        &self,
        node: &Node,
        source: &str,
        depth: usize,
    ) -> Option<String> {
        // Limit recursion depth to prevent stack overflow
        const MAX_DEPTH: usize = 50;
        if depth > MAX_DEPTH {
            return None;
        }

        // Try to find an identifier in the declaration
        if let Some(declarator) = node.child_by_field_name("declarator") {
            return self.get_declarator_name_with_depth(&declarator, source, depth + 1);
        }

        // Fallback: search for identifier node
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    return Some(ast_utils::get_node_text_owned(&child, source));
                }
                if let Some(name) = self.extract_identifier_with_depth(&child, source, depth + 1) {
                    return Some(name);
                }
            }
        }

        None
    }

    #[allow(dead_code)]
    fn get_declarator_name(&self, declarator: &Node, source: &str) -> Option<String> {
        self.get_declarator_name_with_depth(declarator, source, 0)
    }

    fn get_declarator_name_with_depth(
        &self,
        declarator: &Node,
        source: &str,
        depth: usize,
    ) -> Option<String> {
        // Limit recursion depth to prevent stack overflow
        const MAX_DEPTH: usize = 50;
        if depth > MAX_DEPTH {
            return None;
        }

        match declarator.kind() {
            "identifier" => Some(ast_utils::get_node_text_owned(declarator, source)),
            "init_declarator"
            | "pointer_declarator"
            | "array_declarator"
            | "function_declarator" => {
                if let Some(child_declarator) = declarator.child_by_field_name("declarator") {
                    return self.get_declarator_name_with_depth(
                        &child_declarator,
                        source,
                        depth + 1,
                    );
                }

                // Fallback: find identifier child
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if child.kind() == "identifier" {
                            return Some(ast_utils::get_node_text_owned(&child, source));
                        }
                        if let Some(name) =
                            self.get_declarator_name_with_depth(&child, source, depth + 1)
                        {
                            return Some(name);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn get_function_name(&self, declarator: &Node, source: &str) -> Option<String> {
        self.get_function_name_with_depth(declarator, source, 0)
    }

    fn get_function_name_with_depth(
        &self,
        declarator: &Node,
        source: &str,
        depth: usize,
    ) -> Option<String> {
        // Limit recursion depth to prevent stack overflow
        const MAX_DEPTH: usize = 50;
        if depth > MAX_DEPTH {
            return None;
        }

        match declarator.kind() {
            "identifier" => Some(ast_utils::get_node_text_owned(declarator, source)),
            "function_declarator" => {
                if let Some(child_declarator) = declarator.child_by_field_name("declarator") {
                    return self.get_function_name_with_depth(&child_declarator, source, depth + 1);
                }
                None
            }
            "pointer_declarator" => {
                if let Some(child_declarator) = declarator.child_by_field_name("declarator") {
                    return self.get_function_name_with_depth(&child_declarator, source, depth + 1);
                }
                None
            }
            _ => None,
        }
    }

    fn check_visual_similarity(&self, violations: &mut Vec<RuleViolation>) {
        // For each group of identifiers with the same normalized form
        for (normalized, identifiers) in &self.identifiers {
            if identifiers.len() > 1 {
                // Found multiple identifiers with the same normalized form
                // Report all but the first as violations
                for i in 1..identifiers.len() {
                    let (id1, line1, _col1) = &identifiers[0];
                    let (id2, line2, col2) = &identifiers[i];

                    // Only flag when identifiers are actually different strings
                    // that happen to normalize the same (e.g., id_0 vs id_O).
                    // Identical identifiers in different scopes are not a DCL02-C issue.
                    if id1 == id2 {
                        continue;
                    }

                    violations.push(RuleViolation {
                        rule_id: "DCL02-C".to_string(),
                        severity: Severity::Low,
                        message: format!(
                            "Identifier '{}' at line {} is visually similar to '{}' at line {} (normalized: '{}')",
                            id2, line2, id1, line1, normalized
                        ),
                        file_path: String::new(),
                        line: *line2,
                        column: *col2,
                        suggestion: Some(
                            "Use a more distinct identifier name that doesn't rely on visually similar characters".to_string()
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }
}

/// Normalize identifier by replacing visually similar characters with a canonical form
fn normalize_identifier(id: &str) -> String {
    let mut normalized = String::with_capacity(id.len());
    let chars: Vec<char> = id.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];

        // Check for 'rn' sequence (looks like 'm')
        if ch == 'r' && i + 1 < chars.len() && chars[i + 1] == 'n' {
            normalized.push('m'); // Normalize rn -> m
            i += 2;
            continue;
        }

        // Check for 'm' (looks like 'rn')
        if ch == 'm' {
            normalized.push('m'); // Keep m as canonical form
            i += 1;
            continue;
        }

        // Normalize visually similar characters
        let canonical = match ch {
            // 0 (zero) looks like O, Q, D
            '0' | 'O' | 'Q' | 'D' => '0',

            // 1 (one) looks like I (capital i), l (lowercase L)
            '1' | 'I' | 'l' => '1',

            // 2 (two) looks like Z
            '2' | 'Z' => '2',

            // 5 (five) looks like S
            '5' | 'S' => '5',

            // 8 (eight) looks like B
            '8' | 'B' => '8',

            // n looks like h
            'n' | 'h' => 'n',

            // Keep other characters as-is
            c => c,
        };

        normalized.push(canonical);
        i += 1;
    }

    normalized
}
