//! API05-C: Use conformant array parameters
//!
//! Since C99, C supports conformant array parameters with extended syntax that
//! allows specifying array bounds using variables from the parameter list.
//! Conformant array parameters document the expected size relationship and can
//! help compilers and static analysis tools detect buffer overflows.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! // Plain pointer - doesn't document size relationship
//! void my_memset(char* p, size_t n, char v) {
//!     memset(p, v, n);
//! }
//!
//! // Array size uses variable declared AFTER it (invalid)
//! void my_memset(char p[n], size_t n, char v) {
//!     memset(p, v, n);
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! // Size parameter declared BEFORE array parameter
//! void my_memset(size_t n, char p[n], char v) {
//!     memset(p, v, n);
//! }
//!
//! // K&R style with semicolon (GCC extension)
//! void my_memset(size_t n; char p[n], size_t n, char v) {
//!     memset(p, v, n);
//! }
//! ```

use crate::manifest::{RuleCategory, Severity};
use crate::rules::{CertRule, RuleViolation};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

/// Functions whose signature ties a buffer argument to a count/length
/// argument at the call site. Used to establish that a pointer parameter and
/// a size_t parameter are actually associated (task 190) -- without this,
/// the rule previously fired on ANY pointer param whenever the signature had
/// ANY size_t param anywhere, regardless of whether the two were related.
const BUFFER_OP_CALLS: &[&str] = &[
    "memcpy",
    "memmove",
    "memset",
    "memcmp",
    "strncpy",
    "strncat",
    "strncmp",
    "strlcpy",
    "strlcat",
    "snprintf",
    "vsnprintf",
    "read",
    "write",
    "recv",
    "send",
    "fread",
    "fwrite",
];

pub struct Api05C;

impl CertRule for Api05C {
    fn rule_id(&self) -> &'static str {
        "API05-C"
    }

    fn description(&self) -> &'static str {
        "Use conformant array parameters"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "API05-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for decl in query::find_descendants_of_kinds(*node, &["function_definition", "declaration"])
        {
            let body = decl.child_by_field_name("body");
            if let Some(declarator) = decl.child_by_field_name("declarator") {
                self.check_function_declarator(&declarator, source, body.as_ref(), &mut violations);
            }
        }
        violations
    }
}

impl Api05C {
    fn check_function_declarator(
        &self,
        declarator: &Node,
        source: &str,
        body: Option<&Node>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Find function_declarator nodes
        if declarator.kind() == "function_declarator" {
            if let Some(params) = declarator.child_by_field_name("parameters") {
                self.check_parameters(&params, source, body, violations);
            }
        } else if declarator.kind() == "pointer_declarator" {
            // Handle pointer declarators (e.g., *function_name(...))
            if let Some(child) = declarator.named_child(0) {
                self.check_function_declarator(&child, source, body, violations);
            }
        }
    }

    fn check_parameters(
        &self,
        params_node: &Node,
        source: &str,
        body: Option<&Node>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if this uses K&R style (semicolon in parameter list)
        let params_text = get_node_text(params_node, source);
        if params_text.contains(';') {
            // K&R style is compliant, skip check
            return;
        }

        // Collect all parameter info in order
        let mut param_names: Vec<String> = Vec::new();
        let mut param_nodes: Vec<Node> = Vec::new();
        let mut size_t_param_names: Vec<String> = Vec::new();

        for i in 0..params_node.child_count() {
            if let Some(child) = params_node.child(i) {
                if child.kind() == "parameter_declaration" {
                    if let Some(name) = self.get_parameter_name(&child, source) {
                        param_names.push(name.clone());
                        param_nodes.push(child);

                        if let Some(type_node) = child.child_by_field_name("type") {
                            let type_text = get_node_text(&type_node, source);
                            if type_text.contains("size_t") {
                                size_t_param_names.push(name);
                            }
                        }
                    }
                }
            }
        }

        let all_param_names: HashSet<&String> = param_names.iter().collect();

        // Check each parameter for conformant array issues
        for (idx, param_node) in param_nodes.iter().enumerate() {
            let declared_names: HashSet<_> = param_names[..idx].iter().cloned().collect();
            self.check_parameter_conformance(
                param_node,
                &param_names[idx],
                source,
                &declared_names,
                &all_param_names,
                &size_t_param_names,
                body,
                violations,
            );
        }
    }

    fn get_parameter_name(&self, param: &Node, source: &str) -> Option<String> {
        // Try to find the parameter name
        if let Some(declarator) = param.child_by_field_name("declarator") {
            return self.extract_declarator_name(&declarator, source);
        }
        None
    }

    #[allow(clippy::only_used_in_recursion)]
    fn extract_declarator_name(&self, declarator: &Node, source: &str) -> Option<String> {
        match declarator.kind() {
            "identifier" => Some(get_node_text(declarator, source).to_string()),
            "pointer_declarator" | "array_declarator" | "function_declarator" => {
                // Recurse to find the identifier
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if let Some(name) = self.extract_declarator_name(&child, source) {
                            return Some(name);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn check_parameter_conformance(
        &self,
        param: &Node,
        param_name: &str,
        source: &str,
        declared_names: &HashSet<String>,
        all_param_names: &HashSet<&String>,
        size_t_param_names: &[String],
        body: Option<&Node>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(declarator) = param.child_by_field_name("declarator") {
            // Check for plain pointer parameters that could be conformant arrays.
            // Only fire when the function body actually ties this pointer to one
            // of the size_t params as an element count -- a size_t param
            // elsewhere in the signature that's unrelated to this pointer (e.g.
            // an unrelated timeout/flags param) is not evidence of a missed
            // conformant array (task 190).
            if let Some(body) = body {
                if self.is_plain_pointer_param(param, &declarator, source) {
                    if let Some(size_name) = size_t_param_names.iter().find(|n| {
                        Self::body_associates_pointer_with_size(body, source, param_name, n)
                    }) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: format!(
                                "Pointer parameter '{}' should use conformant array syntax bounded by '{}'",
                                param_name, size_name
                            ),
                            file_path: String::new(),
                            line: declarator.start_position().row + 1,
                            column: declarator.start_position().column + 1,
                            suggestion: Some(format!(
                                "Use conformant array parameter syntax (e.g., '{}[{}]') \
                                with the size parameter declared before the array",
                                param_name, size_name
                            )),
                            ..Default::default()
                        });
                    }
                }
            }

            self.check_declarator_conformance(
                &declarator,
                source,
                declared_names,
                all_param_names,
                violations,
            );
        }
    }

    fn is_plain_pointer_param(&self, param: &Node, declarator: &Node, source: &str) -> bool {
        // Check if this is a pointer type (char*, int*, etc.)
        if declarator.kind() != "pointer_declarator" {
            return false;
        }
        // Make sure it's not already an array or function pointer
        if self.has_nested_array_or_function(declarator) {
            return false;
        }
        // Pointer-to-pointer (e.g. `char **out`) is almost always an
        // out-parameter, not a counted buffer -- exclude (task 190).
        if declarator
            .named_child(0)
            .is_some_and(|c| c.kind() == "pointer_declarator")
        {
            return false;
        }
        let Some(type_node) = param.child_by_field_name("type") else {
            return false;
        };
        let type_text = get_node_text(&type_node, source);
        // `void *` is an opaque context pointer with no element type to
        // count -- exclude (task 190).
        if type_text.trim() == "void" {
            return false;
        }
        // A NUL-terminated `const char *` string has no separate count --
        // its own bytes are self-delimiting, so an accompanying size_t param
        // is not evidence it should be a conformant array (task 190). Plain
        // `char`, not `unsigned char`/`signed char` -- those are byte
        // buffers, not conventionally NUL-terminated strings.
        //
        // `const` is a type_qualifier sibling of the "type" field in
        // tree-sitter-c's parameter_declaration grammar, not part of the
        // "type" field itself -- check the whole parameter's text, not just
        // type_text, or this never matches.
        let full_param_text = get_node_text(param, source);
        if full_param_text.contains("const")
            && type_text.contains("char")
            && !type_text.contains("unsigned")
            && !type_text.contains("signed")
        {
            return false;
        }
        // Only flag basic types that are commonly used as buffers
        type_text.contains("char")
            || type_text.contains("void")
            || type_text.contains("unsigned")
            || type_text.contains("int")
    }

    fn has_nested_array_or_function(&self, node: &Node) -> bool {
        query::find_first_descendant(*node, |n| {
            n.kind() == "array_declarator" || n.kind() == "function_declarator"
        })
        .is_some()
    }

    /// True if the function body ties `ptr_name` to `size_name` as an
    /// element count: either `ptr_name` is subscripted by `size_name -
    /// <literal>` (the last-valid-index bounds-check idiom), or both appear
    /// as arguments to the same call to a known buffer-op function
    /// (`memcpy(ptr_name, ..., size_name)`, etc.) (task 190).
    ///
    /// Deliberately excludes a bare `ptr_name[size_name]` subscript (and any
    /// `+`-offset variant): `size_name` there is at least as often a write
    /// cursor/offset into `ptr_name` as it is a bound, e.g. curl's
    /// `add_passwd(..., char *pkt, size_t start, ...)` writes
    /// `pkt[start]`/`pkt[start+1]`/`pkt[start+2]` where `start` is an offset
    /// the caller advances, not pkt's size -- treating any co-occurring
    /// subscript as size evidence produced exactly that false positive.
    fn body_associates_pointer_with_size(
        body: &Node,
        source: &str,
        ptr_name: &str,
        size_name: &str,
    ) -> bool {
        for sub in query::find_descendants_of_kind(*body, "subscript_expression") {
            let Some(arr) = sub.child_by_field_name("argument") else {
                continue;
            };
            if arr.kind() != "identifier" || get_node_text(&arr, source) != ptr_name {
                continue;
            }
            let Some(idx) = sub.child_by_field_name("index") else {
                continue;
            };
            if idx.kind() != "binary_expression" {
                continue;
            }
            let idx_text = get_node_text(&idx, source);
            if Self::dominant_identifier(&idx, source) == size_name
                && idx_text.contains('-')
                && !idx_text.contains('+')
            {
                return true;
            }
        }

        for call in query::find_descendants_of_kind(*body, "call_expression") {
            let Some(func) = call.child_by_field_name("function") else {
                continue;
            };
            let func_name = get_node_text(&func, source);
            if !BUFFER_OP_CALLS.contains(&func_name) {
                continue;
            }
            let Some(args) = call.child_by_field_name("arguments") else {
                continue;
            };
            let mut has_ptr = false;
            let mut has_size = false;
            let mut cursor = args.walk();
            for arg in args.named_children(&mut cursor) {
                let text = get_node_text(&arg, source).trim();
                if text == ptr_name {
                    has_ptr = true;
                }
                if text == size_name {
                    has_size = true;
                }
            }
            if has_ptr && has_size {
                return true;
            }
        }

        false
    }

    /// Find the first identifier in an expression, for resolving the
    /// variable driving an index/size expression like `n - 1`.
    fn dominant_identifier(node: &Node, source: &str) -> String {
        if node.kind() == "identifier" {
            return get_node_text(node, source).to_string();
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    return get_node_text(&child, source).to_string();
                }
            }
        }
        String::new()
    }

    fn check_declarator_conformance(
        &self,
        declarator: &Node,
        source: &str,
        declared_names: &HashSet<String>,
        all_param_names: &HashSet<&String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if declarator.kind() == "array_declarator" {
            // Check if array size uses a variable
            if let Some(size_node) = declarator.child_by_field_name("size") {
                let size_text = get_node_text(&size_node, source).trim();

                // Check if size is a variable (identifier)
                if size_node.kind() == "identifier"
                    || (size_node.kind() == "subscript_expression"
                        && size_node.named_child_count() > 0
                        && size_node
                            .named_child(0)
                            .is_some_and(|n| n.kind() == "identifier"))
                {
                    // Extract variable name
                    let var_name = if size_node.kind() == "identifier" {
                        size_text.to_string()
                    } else if let Some(first_child) = size_node.named_child(0) {
                        get_node_text(&first_child, source).to_string()
                    } else {
                        return;
                    };

                    // A name that isn't a parameter at all (a #define/enum
                    // constant, e.g. `uint64_t H[SHA512_256_HASH_SIZE_WORDS]`)
                    // is not a "declared after" ordering problem -- there is
                    // no such parameter to declare before it (task 190).
                    if !all_param_names.contains(&var_name) {
                        return;
                    }

                    // Check if this variable was declared before this parameter
                    if !declared_names.contains(&var_name) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: format!(
                                "Array parameter uses size variable '{}' that is declared after the array parameter",
                                var_name
                            ),
                            file_path: String::new(),
                            line: declarator.start_position().row + 1,
                            column: declarator.start_position().column + 1,
                            suggestion: Some(format!(
                                "Declare size parameter '{}' before the array parameter, or use K&R style with semicolon",
                                var_name
                            )),
                            ..Default::default()
                        });
                    }
                }
            }
        } else if declarator.kind() == "pointer_declarator" {
            // Recurse to check nested declarators
            for i in 0..declarator.child_count() {
                if let Some(child) = declarator.child(i) {
                    self.check_declarator_conformance(
                        &child,
                        source,
                        declared_names,
                        all_param_names,
                        violations,
                    );
                }
            }
        }
    }
}
