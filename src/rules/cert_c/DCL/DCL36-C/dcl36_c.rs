// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! DCL36-C: Do not declare an identifier with conflicting linkage classifications
//!
//! This rule detects when an identifier is declared with conflicting linkage
//! classifications within a single translation unit. Declaring an identifier
//! with both internal linkage (static) and external linkage (non-static) creates
//! undefined behavior.
//!
//! CERT C reference:
//! <https://wiki.sei.cmu.edu/confluence/display/c/DCL36-C.+Do+not+declare+an+identifier+with+conflicting+linkage+classifications>

use super::super::{CertRule, RuleViolation};
use crate::analyze::preproc_arms::PreprocArms;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::declarator_utils::declares_function;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Linkage {
    Internal, // static
    External, // extern, or no storage-class specifier
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct IdentifierInfo {
    name: String,
    linkage: Linkage,
    line: usize,
    column: usize,
    byte: usize,
}

/// What a declaration's specifiers say about linkage; see
/// `Dcl36C::linkage_specifiers`.
#[derive(Debug, Clone, Copy, Default)]
struct LinkageSpecifiers {
    is_static: bool,
    is_extern: bool,
    is_constexpr: bool,
}

#[derive(Debug)]
pub struct Dcl36C {
    // Track all identifier declarations with their linkage
    declarations: RefCell<HashMap<String, Vec<IdentifierInfo>>>,
    /// The file's `#if` arms, so declarations no translation unit holds
    /// together are not compared.
    arms: RefCell<PreprocArms>,
}

impl Dcl36C {
    pub fn new() -> Self {
        Dcl36C {
            declarations: RefCell::new(HashMap::new()),
            arms: RefCell::new(PreprocArms::default()),
        }
    }

    /// The storage-class specifiers and qualifiers that bear on linkage, as
    /// C23 6.2.2 reads them: `static` (and `constexpr` on an object) gives
    /// internal linkage (p3); `extern` takes the linkage of a visible prior
    /// declaration (p4). `inline`, `thread_local` and the rest name no
    /// linkage, so they leave the declaration where p4/p5 put it.
    fn linkage_specifiers(&self, node: &Node, source: &str) -> LinkageSpecifiers {
        let mut specifiers = LinkageSpecifiers::default();
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match (child.kind(), get_node_text(&child, source)) {
                ("storage_class_specifier", "static") => specifiers.is_static = true,
                ("storage_class_specifier", "extern") => specifiers.is_extern = true,
                ("type_qualifier", "constexpr") => specifiers.is_constexpr = true,
                _ => {}
            }
        }
        specifiers
    }

    /// The linkage one declarator of a file-scope declaration gives its name.
    ///
    /// `None` is "whatever a visible prior declaration says": `extern` (p4),
    /// and a function with no storage-class specifier, which p5 reads as if
    /// it were `extern`. Such a declaration cannot disagree with the
    /// declaration it inherits from, so it is only ever a prior.
    fn declarator_linkage(specifiers: LinkageSpecifiers, declarator: &Node) -> Option<Linkage> {
        let is_function = declares_function(declarator);
        if specifiers.is_static || (specifiers.is_constexpr && !is_function) {
            Some(Linkage::Internal)
        } else if specifiers.is_extern || is_function {
            None
        } else {
            // p5: an object at file scope with no storage-class specifier.
            Some(Linkage::External)
        }
    }

    /// Extract identifier name from a declarator
    fn extract_identifier(&self, declarator: &Node, source: &str) -> Option<String> {
        match declarator.kind() {
            "identifier" => Some(get_node_text(declarator, source).to_string()),
            "pointer_declarator" | "array_declarator" | "function_declarator" => {
                if let Some(inner) = declarator.child_by_field_name("declarator") {
                    return self.extract_identifier(&inner, source);
                }
                None
            }
            "init_declarator" => {
                if let Some(decl) = declarator.child_by_field_name("declarator") {
                    return self.extract_identifier(&decl, source);
                }
                None
            }
            _ => {
                // Try to find identifier child
                let mut cursor = declarator.walk();
                for child in declarator.children(&mut cursor) {
                    if child.kind() == "identifier" {
                        return Some(get_node_text(&child, source).to_string());
                    }
                    if let Some(name) = self.extract_identifier(&child, source) {
                        return Some(name);
                    }
                }
                None
            }
        }
    }

    /// Check if this is a file-scope declaration (not inside a function)
    fn is_file_scope(&self, node: &Node) -> bool {
        // A block directly inside a function is reached on the way to the
        // function itself, so meeting the function settles both questions.
        // One descent for the chain: a climb costs the depth a step.
        !ast_utils::ancestors(node).any(|a| a.kind() == "function_definition")
    }

    /// Process a declaration node
    fn process_declaration(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "declaration" {
            return;
        }

        // Only check file-scope declarations
        if !self.is_file_scope(node) {
            return;
        }

        let specifiers = self.linkage_specifiers(node, source);

        // Extract all identifiers from this declaration
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            let declarator = if child.kind() == "init_declarator" {
                match child.child_by_field_name("declarator") {
                    Some(declarator) => declarator,
                    None => continue,
                }
            } else {
                child
            };
            if let Some(name) = self.extract_identifier(&declarator, source) {
                let linkage = Self::declarator_linkage(specifiers, &declarator);
                self.record_identifier(name, linkage, node, violations);
            }
        }
    }

    /// Record an identifier and check for linkage conflicts.
    ///
    /// A declaration in the other arm of an `#if`/`#else` is not a prior of
    /// this one: no translation unit holds both, so the two never meet.
    fn record_identifier(
        &self,
        name: String,
        linkage: Option<Linkage>,
        node: &Node,
        violations: &mut Vec<RuleViolation>,
    ) {
        let arms = self.arms.borrow();
        let mut decls = self.declarations.borrow_mut();
        let entry = decls.entry(name.clone()).or_default();
        let at = node.start_byte();
        let mut visible = entry.iter().filter(|prev| !arms.exclusive(prev.byte, at));

        let linkage = match linkage {
            Some(linkage) => linkage,
            // p4: the linkage of the prior declaration, or external when
            // none is visible.
            None => visible
                .clone()
                .next_back()
                .map_or(Linkage::External, |prev| prev.linkage),
        };

        // Check if this identifier already has a declaration with different linkage
        if let Some(prev) = visible.find(|prev| prev.linkage != linkage) {
            violations.push(RuleViolation {
                rule_id: "DCL36-C".to_string(),
                severity: Severity::Medium,
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                message: format!(
                    "Identifier '{}' has conflicting linkage: previously declared as {} at line {}, now declared as {}",
                    name,
                    if prev.linkage == Linkage::Internal { "static (internal)" } else { "non-static (external)" },
                    prev.line,
                    if linkage == Linkage::Internal { "static (internal)" } else { "non-static (external)" }
                ),
                file_path: String::new(),
                suggestion: Some(
                    "Use consistent storage-class specifiers for all declarations of the same identifier"
                        .to_string(),
                ),
                requires_manual_review: Some(false),
            });
            return;
        }

        // Record this declaration
        entry.push(IdentifierInfo {
            name,
            linkage,
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            byte: at,
        });
    }

    /// Recursively traverse AST
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            self.process_declaration(&n, source, violations);
        }
    }
}

impl CertRule for Dcl36C {
    fn rule_id(&self) -> &'static str {
        "DCL36-C"
    }

    fn description(&self) -> &'static str {
        "Do not declare an identifier with conflicting linkage classifications"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "DCL36-C"
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.declarations.borrow_mut().clear();
        *self.arms.borrow_mut() = PreprocArms::collect(root);
        self.traverse(root, source, &mut violations);
        violations
    }
}
