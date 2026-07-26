// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! FLP38-C: Avoid undefined behavior while using type-generic macro functions
//!
//! The type-generic macros in `<tgmath.h>` (and the generic functions in
//! `<math.h>`/`<complex.h>` they build on) pick the actual function to call
//! based on the types of their floating-point arguments. Calling one of these
//! macros with arguments whose floating types are incompatible -- notably
//! mixing a decimal floating type (`_Decimal32/64/128`) with a binary one, or
//! mixing two distinct binary floating types (e.g. `_Float32` and
//! `long double`) -- is undefined behavior. Explicitly casting the mismatched
//! argument to a consistent type resolves it.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/FLP38-C.+Avoid+undefined+behavior+while+using+type-generic+macro+functions

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

/// Type-generic macros from <tgmath.h>/<math.h>/<complex.h> whose behavior
/// depends on the (consistent) floating type of their arguments.
const TGMATH_FUNCS: &[&str] = &[
    "acos",
    "asin",
    "atan",
    "atan2",
    "ceil",
    "cos",
    "cosh",
    "exp",
    "fabs",
    "floor",
    "fmod",
    "frexp",
    "ldexp",
    "log",
    "log10",
    "modf",
    "pow",
    "sin",
    "sinh",
    "sqrt",
    "tan",
    "tanh",
    "remainder",
    "copysign",
    "nan",
    "nearbyint",
    "nexttoward",
    "nextafter",
    "fdim",
    "fmax",
    "fmin",
    "hypot",
    "ilogb",
    "lgamma",
    "llrint",
    "llround",
    "log1p",
    "log2",
    "logb",
    "lrint",
    "lround",
    "remquo",
    "rint",
    "round",
    "scalbn",
    "scalbln",
    "tgamma",
    "trunc",
    "cimag",
    "creal",
    "carg",
    "cproj",
];

#[derive(Debug)]
pub struct Flp38C;

impl Flp38C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Flp38C
    }

    /// Build a map of variable name -> declared floating-type spelling, for
    /// every declaration in the file (scope-insensitive; good enough to
    /// resolve simple identifier arguments to a type-generic macro call).
    fn collect_var_types(&self, root: &Node, source: &str, out: &mut HashMap<String, String>) {
        for decl in query::find_descendants_of_kind(*root, "declaration") {
            let Some(type_text) = self.declared_type_text(&decl, source) else {
                continue;
            };
            if !Self::is_floating_type(&type_text) {
                continue;
            }
            for name in query::find_descendants_of_kind(decl, "identifier") {
                // Only the first identifier per init_declarator is the variable
                // name; skip identifiers that are part of an initializer.
                let Some(parent) = name.parent() else {
                    continue;
                };
                let is_declared_name = parent.kind() == "declaration"
                    || (parent.kind() == "init_declarator" && parent.child(0) == Some(name));
                if is_declared_name {
                    out.insert(
                        ast_utils::get_node_text(&name, source).to_string(),
                        type_text.clone(),
                    );
                }
            }
        }
    }

    /// Concatenate the type-specifier tokens of a declaration (everything
    /// before the declarator), e.g. "long double", "_Decimal64", "_Float32".
    fn declared_type_text(&self, decl: &Node, source: &str) -> Option<String> {
        let mut parts = Vec::new();
        for i in 0..decl.child_count() {
            let child = decl.child(i)?;
            match child.kind() {
                "primitive_type" | "type_identifier" => {
                    parts.push(ast_utils::get_node_text(&child, source).to_string());
                }
                "sized_type_specifier" => {
                    parts.push(ast_utils::get_node_text(&child, source).to_string());
                }
                "init_declarator" | "identifier" => break,
                _ => {}
            }
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }

    fn is_floating_type(type_text: &str) -> bool {
        matches!(
            type_text,
            "float"
                | "double"
                | "long double"
                | "_Float16"
                | "_Float32"
                | "_Float64"
                | "_Float128"
                | "_Decimal32"
                | "_Decimal64"
                | "_Decimal128"
        )
    }

    fn traverse(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut var_types = HashMap::new();
        self.collect_var_types(root, source, &mut var_types);

        for call in query::find_descendants_of_kind(*root, "call_expression") {
            let Some(func) = call.child_by_field_name("function") else {
                continue;
            };
            if func.kind() != "identifier" {
                continue;
            }
            let func_name = ast_utils::get_node_text(&func, source);
            if !TGMATH_FUNCS.contains(&func_name) {
                continue;
            }
            let Some(args) = call.child_by_field_name("arguments") else {
                continue;
            };

            let mut distinct_types: Vec<String> = Vec::new();
            let mut cursor = args.walk();
            for arg in args.named_children(&mut cursor) {
                // A cast normalizes the argument's type; only uncast plain
                // identifiers are checked against each other for a mismatch.
                if arg.kind() != "identifier" {
                    continue;
                }
                let name = ast_utils::get_node_text(&arg, source);
                if let Some(ty) = var_types.get(name) {
                    if !distinct_types.contains(ty) {
                        distinct_types.push(ty.clone());
                    }
                }
            }

            if distinct_types.len() > 1 {
                let pos = call.start_position();
                violations.push(RuleViolation {
                    rule_id: "FLP38-C".to_string(),
                    severity: Severity::Medium,
                    line: pos.row + 1,
                    column: pos.column + 1,
                    message: format!(
                        "call to type-generic macro '{}' mixes incompatible floating argument types ({}) -- undefined behavior",
                        func_name,
                        distinct_types.join(", ")
                    ),
                    file_path: String::new(),
                    suggestion: Some(
                        "Explicitly cast the arguments to a common floating type before calling this type-generic macro"
                            .to_string(),
                    ),
                    requires_manual_review: Some(false),
                });
            }
        }
    }
}

impl CertRule for Flp38C {
    fn rule_id(&self) -> &'static str {
        "FLP38-C"
    }

    fn description(&self) -> &'static str {
        "Avoid undefined behavior while using type-generic macro functions"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "FLP38-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
