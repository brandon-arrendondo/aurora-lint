//! API02-C: Functions that read or write to or from an array should take an argument
//! to specify the source or target size
//!
//! This rule detects function declarations where array/pointer parameters are not
//! accompanied by size parameters. Functions operating on arrays must accept an
//! additional parameter indicating maximum element count to prevent buffer overflows.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! char *strncpy(char *s1, const char *s2, size_t n);
//! // s1 and s2 are arrays, but no size parameters for them
//! // 'n' is copy count, not array capacity
//! ```
//!
//! **Compliant:**
//! ```c
//! char *improved_strncpy(char *s1, size_t s1count,
//!                        const char *s2, size_t s2count, size_t n);
//! // Each array has explicit size parameter
//! ```
//!
//! ## Detection Strategy:
//! - Find function_declarator nodes
//! - Identify pointer parameters (potential arrays)
//! - Check if immediately followed by size_t parameter
//! - Report if pointer lacks corresponding size parameter

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::declarator_utils::is_pointer_declarator;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Api02C;

impl CertRule for Api02C {
    fn rule_id(&self) -> &'static str {
        "API02-C"
    }

    fn description(&self) -> &'static str {
        "Functions that read or write to or from an array should take an argument to specify the source or target size"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "API02-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for decl in query::find_descendants_of_kind(*node, "declaration") {
            if let Some(declarator) = decl.child_by_field_name("declarator") {
                if self.is_function_declarator(&declarator) {
                    self.check_function_parameters(&declarator, &decl, source, &mut violations);
                }
            }
        }
        violations
    }
}

impl Api02C {
    fn is_function_declarator(&self, node: &Node) -> bool {
        query::find_first_descendant(*node, |n| n.kind() == "function_declarator").is_some()
    }

    fn check_function_parameters(
        &self,
        declarator: &Node,
        declaration: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        self.check_parameters_recursive(declarator, declaration, source, violations);
    }

    /// Uses an explicit stack instead of recursion. The prune at
    /// `parameter_list` (deliberately not descending into a matched list's
    /// own children, to avoid double-counting nested function-pointer
    /// params) keeps this bounded in practice, but depth outside a matched
    /// list is otherwise unbounded native recursion -- the same risk class
    /// as the original ARR00-C/MEM33-C bug (task 153).
    fn check_parameters_recursive(
        &self,
        root: &Node,
        declaration: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let mut stack = vec![*root];
        while let Some(node) = stack.pop() {
            // Found parameter_list
            if node.kind() == "parameter_list" {
                // Collect all parameters
                let mut params = Vec::new();
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "parameter_declaration" {
                            params.push(child);
                        }
                    }
                }

                // Check each pointer parameter for missing size
                for i in 0..params.len() {
                    let is_last = i + 1 >= params.len();
                    if self.is_pointer_parameter(&params[i], source, is_last) {
                        // Check if next parameter is size_t
                        if is_last || !self.is_size_t_parameter(&params[i + 1], source) {
                            self.report_violation(declaration, &params[i], source, violations);
                        }
                    }
                }
                continue;
            }

            // Queue children for searching
            for i in (0..node.child_count()).rev() {
                if let Some(child) = node.child(i) {
                    stack.push(child);
                }
            }
        }
    }

    fn is_pointer_parameter(&self, param: &Node, source: &str, is_last: bool) -> bool {
        // Get the type
        let type_node = match param.child_by_field_name("type") {
            Some(t) => t,
            None => return false,
        };

        let type_text = get_node_text(&type_node, source);

        // Skip const char * parameters — these are conventionally null-terminated
        // string inputs that use the null terminator as bounds, not explicit size.
        // This matches standard C conventions (strcmp, strdup, printf format, etc.)
        let param_text = get_node_text(param, source);
        let normalized = param_text.split_whitespace().collect::<Vec<_>>().join(" ");
        if normalized.starts_with("const char *") || normalized.starts_with("const char*") {
            return false;
        }
        // Also handle the tree-sitter pattern where const is a type_qualifier
        // and char is the type — check if type is "char" and there's a const qualifier
        if type_text == "char" {
            let mut has_const = false;
            for i in 0..param.child_count() {
                if let Some(child) = param.child(i) {
                    if child.kind() == "type_qualifier" {
                        let q = get_node_text(&child, source);
                        if q == "const" {
                            has_const = true;
                        }
                    }
                }
            }
            if has_const {
                if let Some(declarator) = param.child_by_field_name("declarator") {
                    if is_pointer_declarator(&declarator) {
                        return false;
                    }
                }
            }
        }
        // Skip const wchar_t * — wide string equivalent of const char *
        if type_text == "wchar_t" {
            let mut has_const = false;
            for i in 0..param.child_count() {
                if let Some(child) = param.child(i) {
                    if child.kind() == "type_qualifier" && get_node_text(&child, source) == "const"
                    {
                        has_const = true;
                    }
                }
            }
            if has_const {
                if let Some(declarator) = param.child_by_field_name("declarator") {
                    if is_pointer_declarator(&declarator) {
                        return false;
                    }
                }
            }
        }

        // Skip pointers to user-defined/struct types — these are almost always
        // single-object pointers (OOP "self"/"this"), not arrays.
        // Only flag pointers to primitive/builtin types that could be arrays.
        if self.is_user_defined_type(&type_text) {
            return false;
        }

        // Skip void * parameters — in C, void * without a size parameter is virtually
        // always a type-erased single object (OOP "self", generic item, etc.), not an
        // array. When void * IS used for arrays (memcpy, fread), the size is always present.
        if type_text == "void" {
            if let Some(declarator) = param.child_by_field_name("declarator") {
                if is_pointer_declarator(&declarator) {
                    return false;
                }
            }
        }

        // Skip bool * and _Bool * parameters — these are single-element output parameters
        // (the caller passes &flag for the function to write a result), never arrays.
        if type_text == "bool" || type_text == "_Bool" {
            if let Some(declarator) = param.child_by_field_name("declarator") {
                if is_pointer_declarator(&declarator) {
                    return false;
                }
            }
        }

        // Skip a trailing pointer-to-scalar-arithmetic-type parameter — the
        // well-established "single-value output parameter" C convention
        // (`int *out`, `size_t *n`, `long *ms`) where the pointee is
        // inherently bounded to one object: with nothing after it in the
        // signature, there is no possible size argument for it to pair
        // with, so a memory-safe implementation can only ever write one
        // element through it. Only applies when this is the LAST
        // parameter — the same pointee type earlier in the list, followed
        // by other parameters that could have been (but weren't) its
        // size, is still the genuine strncpy-style violation this rule
        // targets. Confirmed via 589 adjudicated real-world API02-C false
        // positives (task 450): sqlite's pRes/pResOut/pAmt/pMask/pnOpt,
        // curl's curl_easy_recv's `size_t *n`, curl_multi_perform's
        // `int *running_handles`, curl_multi_timeout's `long *milliseconds`
        // — every one a trailing scalar-typed out-pointer with no
        // possible size parameter anywhere in the signature.
        if is_last && self.is_scalar_arithmetic_type(&type_text) {
            if let Some(declarator) = param.child_by_field_name("declarator") {
                if is_pointer_declarator(&declarator) {
                    return false;
                }
            }
        }

        // Check for pointer type
        if type_text.contains('*') {
            // Exclude function pointers (they're not arrays)
            if !type_text.contains("(*") && !type_text.contains("(* ") {
                return true;
            }
        }

        // Check declarator for pointer
        if let Some(declarator) = param.child_by_field_name("declarator") {
            if is_pointer_declarator(&declarator) {
                return true;
            }
        }

        false
    }

    /// True for a plain arithmetic/integer scalar type — the set of pointee
    /// types conventionally used for single-value output parameters
    /// (`int *out`, `size_t *n`). Deliberately excludes `char`/`wchar_t`
    /// (retain their array/string-buffer semantics elsewhere in this file)
    /// and `bool`/`_Bool`/`void` (already handled by their own dedicated
    /// checks above).
    fn is_scalar_arithmetic_type(&self, type_text: &str) -> bool {
        matches!(
            type_text,
            "int"
                | "short"
                | "long"
                | "long long"
                | "unsigned"
                | "signed"
                | "unsigned int"
                | "unsigned short"
                | "unsigned long"
                | "unsigned long long"
                | "signed int"
                | "signed short"
                | "signed long"
                | "signed long long"
                | "float"
                | "double"
                | "int8_t"
                | "int16_t"
                | "int32_t"
                | "int64_t"
                | "uint8_t"
                | "uint16_t"
                | "uint32_t"
                | "uint64_t"
                | "size_t"
                | "ssize_t"
                | "ptrdiff_t"
                | "intptr_t"
                | "uintptr_t"
        )
    }

    /// Check if a type name is a user-defined type (struct, union, typedef, enum)
    /// rather than a C primitive type. User-defined type pointers are almost always
    /// single-object pointers, not arrays, so API02-C shouldn't flag them.
    fn is_user_defined_type(&self, type_text: &str) -> bool {
        // Strip const/volatile/restrict qualifiers and whitespace
        let stripped = type_text
            .replace("const", "")
            .replace("volatile", "")
            .replace("restrict", "")
            .replace("struct", "")
            .replace("union", "")
            .replace("enum", "")
            .trim()
            .to_string();

        // Explicit struct/union/enum keyword → user-defined
        if type_text.contains("struct ")
            || type_text.contains("union ")
            || type_text.contains("enum ")
        {
            return true;
        }

        // C primitive types and stdint types that could be used for arrays
        let primitive_types = [
            "char",
            "int",
            "short",
            "long",
            "float",
            "double",
            "void",
            "signed",
            "unsigned",
            "_Bool",
            "bool",
            // stdint types
            "int8_t",
            "int16_t",
            "int32_t",
            "int64_t",
            "uint8_t",
            "uint16_t",
            "uint32_t",
            "uint64_t",
            "size_t",
            "ssize_t",
            "ptrdiff_t",
            "intptr_t",
            "uintptr_t",
            "wchar_t",
            // Common C99/POSIX types
            "FILE",
        ];

        !primitive_types.iter().any(|p| stripped == *p)
    }

    fn is_size_t_parameter(&self, param: &Node, source: &str) -> bool {
        let type_node = match param.child_by_field_name("type") {
            Some(t) => t,
            None => return false,
        };

        let type_text = get_node_text(&type_node, source);

        // Accept size_t and common integer types used for sizes in embedded codebases
        matches!(
            type_text,
            "size_t"
                | "uint32_t"
                | "uint16_t"
                | "uint8_t"
                | "int32_t"
                | "int"
                | "unsigned"
                | "unsigned int"
                | "rsize_t"
        )
    }

    fn report_violation(
        &self,
        declaration: &Node,
        pointer_param: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let param_text = get_node_text(pointer_param, source);
        let decl_text = get_node_text(declaration, source);

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "Function has pointer parameter without size argument: '{}' - Add size_t parameter to specify array capacity",
                decl_text.lines().next().unwrap_or(decl_text).trim()
            ),
            file_path: String::new(),
            line: declaration.start_position().row + 1,
            column: declaration.start_position().column + 1,
            suggestion: Some(format!(
                "Add a size_t parameter after '{}' to specify the maximum number of elements in the array",
                param_text.trim()
            )),
            ..Default::default()
        });
    }
}
