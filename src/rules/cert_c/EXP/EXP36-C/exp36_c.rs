use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::macro_expand::{collect_function_macros, FunctionMacro};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use regex::Regex;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Exp36C {
    /// Struct/typedef names known to be `__attribute__((packed))` (or the
    /// project's packed-struct macro) across ALL scanned files, from
    /// prescan (task 395). Needed because the struct's *definition* usually
    /// lives in a header, not the file containing the cast being checked.
    packed_structs: RefCell<HashSet<String>>,
}

impl Exp36C {
    pub fn new() -> Self {
        Self {
            packed_structs: RefCell::new(HashSet::new()),
        }
    }
}

impl Default for Exp36C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Exp36C {
    fn rule_id(&self) -> &'static str {
        "EXP36-C"
    }

    fn description(&self) -> &'static str {
        "Do not cast pointers into more strictly aligned pointer types"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP36-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.packed_structs.borrow_mut() = context.packed_structs.clone();
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let macros = collect_function_macros(node, source);

        for descendant in query::find_descendants_of_kinds(
            *node,
            &["cast_expression", "init_declarator", "call_expression"],
        ) {
            match descendant.kind() {
                // Pattern 1: Direct casts - (int *)&c or (struct foo *)data
                "cast_expression" => {
                    self.check_cast_expression(&descendant, node, source, &mut violations);
                }
                // Pattern 2: Init declarators with function calls returning void* from less-aligned types
                "init_declarator" => {
                    self.check_init_declarator(&descendant, source, &mut violations);
                }
                // Pattern 3: Calls to function-like macros that internally cast
                // one of their parameters to a pointer type, e.g.
                // #define READ_UINT16(ptr) (*(uint16_t *)(ptr)) -- the cast is
                // invisible to Pattern 1 because aurora-lint has no preprocessor and
                // the macro body is opaque replacement-list text, not parsed
                // expression nodes.
                "call_expression" => {
                    self.check_macro_cast_invocation(
                        &descendant,
                        node,
                        &macros,
                        source,
                        &mut violations,
                    );
                }
                _ => {}
            }
        }

        violations
    }
}

impl Exp36C {
    /// Check cast expressions for alignment violations
    fn check_cast_expression(
        &self,
        node: &Node,
        root: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the type being cast to
        if let Some(type_node) = node.child_by_field_name("type") {
            let target_type = ast_utils::get_node_text(&type_node, source).trim();

            // EXP36-C is about pointer-to-pointer casts — skip non-pointer target types
            // e.g., (unsigned)time(NULL) is an integer cast, not a pointer alignment issue
            if !target_type.contains('*') {
                return;
            }

            let target_alignment = self.effective_type_alignment(target_type, root, source);

            // Get the value being cast
            if let Some(value_node) = node.child_by_field_name("value") {
                let source_type = self.infer_pointer_type(&value_node, source);

                // Skip if source is not actually a pointer type
                if source_type == "unknown *" {
                    return;
                }

                let source_alignment = self.get_type_alignment(&source_type);

                // Check if we're casting to a more strictly aligned type
                if target_alignment > source_alignment && source_alignment > 0 {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: "EXP36-C".to_string(),
                        severity: Severity::Low,
                        message: format!(
                            "Casting from {} (alignment {}) to {} (alignment {}) may cause alignment issues",
                            source_type, source_alignment, target_type, target_alignment
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Use memcpy or ensure proper alignment before casting".to_string()
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check a call to a (potential) function-like macro that internally
    /// casts one of its parameters to a pointer type. If the macro's
    /// replacement-list text contains a pattern like `(TYPE *)(param)` where
    /// `param` is one of its declared parameters, and the actual argument at
    /// this call site has a real declared type less strictly aligned than
    /// TYPE, flag it the same way a direct cast would be.
    fn check_macro_cast_invocation(
        &self,
        node: &Node,
        root: &Node,
        macros: &HashMap<String, FunctionMacro>,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(function_node) = node.child_by_field_name("function") else {
            return;
        };
        let func_name = ast_utils::get_node_text(&function_node, source)
            .trim()
            .to_string();
        let Some(macro_def) = macros.get(&func_name) else {
            return;
        };
        let Some((param_idx, target_type)) = self.macro_casts_param_to_pointer(macro_def) else {
            return;
        };
        let target_alignment = self.effective_type_alignment(&target_type, root, source);
        if target_alignment == 0 {
            return;
        }

        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        let named_args: Vec<Node> = arguments.named_children(&mut cursor).collect();
        let Some(arg_node) = named_args.get(param_idx) else {
            return;
        };
        // Only simple identifier arguments are resolved for now (covers the
        // common "pass a declared pointer variable into an accessor macro"
        // pattern); anything more complex is left unflagged to avoid FPs.
        if arg_node.kind() != "identifier" {
            return;
        }
        let arg_name = ast_utils::get_node_text(arg_node, source)
            .trim()
            .to_string();
        let Some((base_type, is_pointer, _)) = self.resolve_declared_type(&arg_name, node, source)
        else {
            return;
        };
        if !is_pointer {
            return;
        }
        let source_type = format!("{} *", base_type);
        let source_alignment = self.get_type_alignment(&source_type);

        if target_alignment > source_alignment && source_alignment > 0 {
            let start_point = node.start_position();
            violations.push(RuleViolation {
                rule_id: "EXP36-C".to_string(),
                severity: Severity::Low,
                message: format!(
                    "Macro '{}' casts argument '{}' from {} (alignment {}) to {} (alignment {}), which may cause alignment issues",
                    func_name, arg_name, source_type, source_alignment, target_type, target_alignment
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(
                    "Ensure the argument's underlying storage is properly aligned before passing it to this macro".to_string()
                ),
                ..Default::default()
            });
        }
    }

    /// If `m`'s replacement-list text casts one of its own parameters to a
    /// pointer type (e.g. `(*(uint16_t *)(ptr))`), return that parameter's
    /// index and the cast-to pointer type text (e.g. `"uint16_t *"`).
    fn macro_casts_param_to_pointer(&self, m: &FunctionMacro) -> Option<(usize, String)> {
        let re = Regex::new(
            r"\(\s*([A-Za-z_][A-Za-z0-9_ ]*?)\s*\*\s*\)\s*\(?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)?",
        )
        .ok()?;
        for cap in re.captures_iter(&m.body) {
            let target_type = cap[1].trim().to_string();
            let arg_name = &cap[2];
            if let Some(idx) = m.params.iter().position(|p| p == arg_name) {
                return Some((idx, format!("{} *", target_type)));
            }
        }
        None
    }

    /// Resolve the real declared type of a simple identifier by walking up
    /// to the enclosing function's parameters and local declarations, rather
    /// than guessing from the identifier's spelling. Returns
    /// `(base_type, is_declared_pointer, alignas_type)` where `alignas_type`
    /// is the type named in an `alignas(...)`/`_Alignas(...)` qualifier on
    /// the declaration, if present.
    fn resolve_declared_type(
        &self,
        name: &str,
        node: &Node,
        source: &str,
    ) -> Option<(String, bool, Option<String>)> {
        let mut current = node.parent();
        while let Some(n) = current {
            if n.kind() == "function_definition" {
                if let Some(declarator) = n.child_by_field_name("declarator") {
                    if let Some(params) = self.find_parameter_list(&declarator) {
                        let mut cursor = params.walk();
                        for p in params.named_children(&mut cursor) {
                            if p.kind() != "parameter_declaration" {
                                continue;
                            }
                            if let Some(d) = p.child_by_field_name("declarator") {
                                if self.declarator_name_matches(&d, source, name) {
                                    let type_text = p
                                        .child_by_field_name("type")
                                        .map(|t| {
                                            ast_utils::get_node_text(&t, source).trim().to_string()
                                        })
                                        .unwrap_or_default();
                                    return Some((
                                        type_text,
                                        self.has_pointer_declarator(&d),
                                        None,
                                    ));
                                }
                            }
                        }
                    }
                }
                // Local-variable case: use the scope- and shadowing-aware
                // lookup (nearest enclosing block, walking outward) instead
                // of a flat scan of every declaration in the function body —
                // that flat scan couldn't distinguish two same-named locals
                // declared in sibling blocks (e.g. an if/else with different
                // types for `x` in each branch).
                if let Some(decl) =
                    ast_utils::find_enclosing_declaration_for_identifier(node, name, source)
                {
                    let mut cursor = decl.walk();
                    for child in decl.children(&mut cursor) {
                        let declarator_opt = if child.kind() == "init_declarator" {
                            child.child_by_field_name("declarator")
                        } else if matches!(
                            child.kind(),
                            "identifier" | "pointer_declarator" | "array_declarator"
                        ) {
                            Some(child)
                        } else {
                            None
                        };
                        if let Some(d) = declarator_opt {
                            if self.declarator_name_matches(&d, source, name) {
                                let type_text = decl
                                    .child_by_field_name("type")
                                    .map(|t| {
                                        ast_utils::get_node_text(&t, source).trim().to_string()
                                    })
                                    .unwrap_or_default();
                                let alignas_type = self.declaration_alignas_type(&decl, source);
                                return Some((
                                    type_text,
                                    self.has_pointer_declarator(&d),
                                    alignas_type,
                                ));
                            }
                        }
                    }
                }
                return None;
            }
            current = n.parent();
        }
        None
    }

    /// Find the `function_declarator`'s `parameters` field, unwrapping any
    /// pointer-return `pointer_declarator` wrapper.
    fn find_parameter_list<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        match node.kind() {
            "function_declarator" => node.child_by_field_name("parameters"),
            "pointer_declarator" => node
                .child_by_field_name("declarator")
                .and_then(|d| self.find_parameter_list(&d)),
            _ => None,
        }
    }

    /// True if `declarator` (an `identifier`, or a nested
    /// pointer/array declarator wrapping one) is named `name`.
    fn declarator_name_matches(&self, declarator: &Node, source: &str, name: &str) -> bool {
        match declarator.kind() {
            "identifier" => ast_utils::get_node_text(declarator, source).trim() == name,
            "pointer_declarator" | "array_declarator" => declarator
                .child_by_field_name("declarator")
                .map(|d| self.declarator_name_matches(&d, source, name))
                .unwrap_or(false),
            _ => false,
        }
    }

    /// If `declaration` carries an `alignas`/`_Alignas` qualifier, return the
    /// type named inside it (e.g. `alignas(int) char c;` -> `Some("int")`).
    fn declaration_alignas_type(&self, declaration: &Node, source: &str) -> Option<String> {
        // alignas_qualifier is nested inside a type_qualifier wrapper, not a
        // direct child of declaration, so search all descendants (safe here:
        // a declaration node never contains nested statements).
        for qualifier in query::find_descendants_of_kind(*declaration, "alignas_qualifier") {
            let mut inner_cursor = qualifier.walk();
            for inner in qualifier.named_children(&mut inner_cursor) {
                if inner.kind() == "type_descriptor" {
                    return Some(ast_utils::get_node_text(&inner, source).trim().to_string());
                }
            }
        }
        None
    }

    /// Check init declarators for indirect casts through void*
    /// Pattern: int *int_ptr = loop_function(char_ptr);
    /// where loop_function takes void* and returns void*/int*
    fn check_init_declarator(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the declarator type
        if let Some(declarator) = node.child_by_field_name("declarator") {
            let var_type = self.extract_pointer_type_from_declarator(&declarator, source);

            // EXP36-C is about alignment-increasing conversions into a
            // pointer variable. If the declarator isn't actually a pointer
            // (e.g. `int res = some_call(...)`), there's no pointer target
            // type at all, so `check_void_pointer_conversion` would compare
            // a call argument's alignment against an unrelated scalar type
            // and fabricate a violation (sqlite whereexpr.c:1532 -- `int
            // res = isAuxiliaryVtabOperator(...)` was flagged this way with
            // no pointer cast anywhere in the statement).
            if !var_type.contains('*') {
                return;
            }

            // Get the value being assigned (often a function call)
            if let Some(value) = node.child_by_field_name("value") {
                if value.kind() == "call_expression" {
                    // Check if the function returns void* and the argument is a less-aligned type
                    self.check_void_pointer_conversion(&value, &var_type, source, violations);
                }
            }
        }
    }

    /// Check for conversions through void* that increase alignment
    fn check_void_pointer_conversion(
        &self,
        call_node: &Node,
        target_type: &str,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let target_alignment = self.get_type_alignment(target_type);

        // Get the function arguments
        if let Some(arguments) = call_node.child_by_field_name("arguments") {
            for i in 0..arguments.child_count() {
                if let Some(arg) = arguments.child(i) {
                    if arg.kind() == "identifier" || arg.kind() == "pointer_expression" {
                        let arg_type = self.infer_pointer_type(&arg, source);
                        let arg_alignment = self.get_type_alignment(&arg_type);

                        // Only flag if we can definitively determine the argument is less-aligned
                        // Skip "unknown *" types to avoid false positives
                        if arg_type != "unknown *"
                            && target_alignment > arg_alignment
                            && arg_alignment > 0
                            && arg_alignment < 4
                        {
                            let start_point = call_node.start_position();
                            violations.push(RuleViolation {
                                rule_id: "EXP36-C".to_string(),
                                severity: Severity::Low,
                                message: format!(
                                    "Potential alignment violation: passing {} (alignment {}) through function to {} (alignment {})",
                                    arg_type, arg_alignment, target_type, target_alignment
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some(
                                    "Ensure function maintains proper pointer alignment or use properly aligned intermediate objects".to_string()
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    /// Extract pointer type from declarator
    fn extract_pointer_type_from_declarator(&self, declarator: &Node, source: &str) -> String {
        // Walk up the tree to find the type
        if let Some(parent) = declarator.parent() {
            if parent.kind() == "init_declarator" {
                if let Some(grandparent) = parent.parent() {
                    if grandparent.kind() == "declaration" {
                        // Get type from declaration
                        for i in 0..grandparent.child_count() {
                            if let Some(child) = grandparent.child(i) {
                                if child.kind() == "type_descriptor"
                                    || child.kind() == "primitive_type"
                                    || child.kind() == "struct_specifier"
                                    || child.kind() == "sized_type_specifier"
                                {
                                    let type_text = ast_utils::get_node_text(&child, source);
                                    // Check if declarator has pointer_declarator
                                    if self.has_pointer_declarator(declarator) {
                                        return format!("{} *", type_text.trim());
                                    }
                                    return type_text.trim().to_string();
                                }
                            }
                        }
                    }
                }
            }
        }
        String::from("unknown")
    }

    /// Check if a declarator is a pointer declarator
    fn has_pointer_declarator(&self, node: &Node) -> bool {
        if node.kind() == "pointer_declarator" {
            return true;
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if self.has_pointer_declarator(&child) {
                    return true;
                }
            }
        }
        false
    }

    /// Infer the pointer type from a node (for expressions like &c, char_ptr, etc.)
    fn infer_pointer_type(&self, node: &Node, source: &str) -> String {
        match node.kind() {
            "parenthesized_expression" => {
                // Unwrap parentheses: (data + offset) -> data + offset
                if let Some(inner) = node.child(1) {
                    return self.infer_pointer_type(&inner, source);
                }
                "unknown *".to_string()
            }
            "pointer_expression" => {
                // Pattern: &c -- taking the address of a (non-pointer)
                // variable produces a pointer whose alignment is the
                // variable's own alignment, which may have been raised by
                // an `alignas`/`_Alignas` qualifier on its declaration.
                if let Some(arg) = node.child_by_field_name("argument") {
                    if arg.kind() == "identifier" {
                        let name = ast_utils::get_node_text(&arg, source).trim().to_string();
                        if let Some((base_type, is_pointer, alignas_type)) =
                            self.resolve_declared_type(&name, node, source)
                        {
                            if !is_pointer {
                                let effective_type = alignas_type.unwrap_or(base_type);
                                return format!("{} *", effective_type);
                            }
                        }
                    }
                    // Fall back to the name-based heuristic when the
                    // declaration couldn't be resolved.
                    let arg_text = ast_utils::get_node_text(&arg, source);
                    if arg_text.contains("char") || arg_text == "c" {
                        return "char *".to_string();
                    }
                }
                "unknown *".to_string()
            }
            "identifier" => {
                let id_text = ast_utils::get_node_text(node, source);
                // Heuristic based on variable names
                if id_text.contains("char")
                    || id_text.ends_with("_ptr") && id_text.starts_with("char")
                {
                    "char *".to_string()
                } else if id_text.contains("int") {
                    "int *".to_string()
                } else if id_text.contains("data") {
                    // Common pattern for char buffers
                    "char *".to_string()
                } else {
                    "unknown *".to_string()
                }
            }
            "binary_expression" => {
                // Pattern: data + offset
                if let Some(left) = node.child_by_field_name("left") {
                    return self.infer_pointer_type(&left, source);
                }
                "char *".to_string() // Common pattern for pointer arithmetic
            }
            _ => "unknown *".to_string(),
        }
    }

    /// Alignment of `type_str`, adjusted for `__attribute__((packed))` /
    /// `STRUCT_PACKED`-style struct definitions: a packed struct's actual
    /// alignment is 1 regardless of its members, so a cast into it can never
    /// be an alignment-*increasing* cast. Checks the struct's definition in
    /// this file's own AST first (covers single-TU test fixtures), then
    /// falls back to the cross-file `packed_structs` set gathered by
    /// prescan (covers the common case where the struct is defined in a
    /// header, not the file containing the cast).
    fn effective_type_alignment(&self, type_str: &str, root: &Node, source: &str) -> usize {
        let mut normalized = type_str.trim().trim_end_matches('*').trim();
        loop {
            let stripped = ["const ", "volatile "]
                .iter()
                .find_map(|q| normalized.strip_prefix(q));
            match stripped {
                Some(rest) => normalized = rest.trim(),
                None => break,
            }
        }
        if let Some(struct_name) = normalized.strip_prefix("struct ") {
            let struct_name = struct_name.trim();
            if let Some(def) = self.find_struct_definition(root, struct_name, source) {
                if ast_utils::struct_specifier_is_packed(&def, source) {
                    return 1;
                }
            } else if self.packed_structs.borrow().contains(struct_name) {
                return 1;
            }
        }
        self.get_type_alignment(type_str)
    }

    /// Find the (defining, i.e. has a body) `struct_specifier` for `name`
    /// anywhere in the translation unit.
    fn find_struct_definition<'a>(
        &self,
        root: &Node<'a>,
        name: &str,
        source: &str,
    ) -> Option<Node<'a>> {
        for s in query::find_descendants_of_kind(*root, "struct_specifier") {
            if s.child_by_field_name("body").is_none() {
                continue;
            }
            if let Some(n) = s.child_by_field_name("name") {
                if ast_utils::get_node_text(&n, source).trim() == name {
                    return Some(s);
                }
            }
        }
        None
    }

    /// Normalize a type string for alignment-table lookup: strip `const`/
    /// `volatile` qualifiers (wherever they appear, e.g. `const uint8_t *`
    /// or `unsigned char * const`) and collapse whitespace so `uint8_t*`,
    /// `uint8_t *`, and `uint8_t  *` all normalize to the same lookup key.
    /// Without this, a qualified target type like `const uint8_t *` never
    /// matched the map's `"uint8_t *"` entry, silently fell through to the
    /// "pointer type not in map -> assume 4-byte alignment" default, and
    /// fabricated an alignment mismatch for byte-sized types (task 572).
    fn normalize_type_for_alignment_lookup(&self, type_str: &str) -> String {
        let trimmed = type_str.trim();
        let is_pointer = trimmed.ends_with('*');
        let base = trimmed.trim_end_matches('*').trim();
        let words: Vec<&str> = base
            .split_whitespace()
            .filter(|w| *w != "const" && *w != "volatile")
            .collect();
        let base_norm = words.join(" ");
        if is_pointer {
            format!("{} *", base_norm)
        } else {
            base_norm
        }
    }

    /// Get alignment requirements for a type
    /// Returns alignment in bytes
    fn get_type_alignment(&self, type_str: &str) -> usize {
        // Create a map of types to alignments
        let alignments: HashMap<&str, usize> = [
            ("char", 1),
            ("char *", 1),
            ("unsigned char", 1),
            ("unsigned char *", 1),
            ("signed char", 1),
            ("signed char *", 1),
            // Fixed-width byte types — alignment 1 (same as char)
            ("uint8_t", 1),
            ("uint8_t *", 1),
            ("int8_t", 1),
            ("int8_t *", 1),
            // Linux/hostap-style fixed-width kernel typedefs (u8/u16/u32/u64,
            // s8/s16/s32/s64, and the byte-order-tagged be16/le16/be32/le32/
            // be64/le64 wrappers around u16/u32/u64) — same alignment as the
            // stdint types they're defined from. Absent these, an unmatched
            // pointer type fell through to the "assume 4-byte alignment"
            // default below, fabricating an alignment-1-to-4 violation for
            // every `u8 *`/`s8 *` cast — a single root cause behind a large,
            // recurring EXP36-C false-positive class across the hostap
            // corpus (see data/precision_audit/hostap/categorical_patterns.md,
            // e.g. `taxonomy.c:73`/`upnp_xml.c:125`/driver_ndis.c's `(const u8 *)`
            // casts/eap_server_tls_common.c's `test_sha384`).
            ("u8", 1),
            ("u8 *", 1),
            ("s8", 1),
            ("s8 *", 1),
            ("u16", 2),
            ("u16 *", 2),
            ("s16", 2),
            ("s16 *", 2),
            ("be16", 2),
            ("be16 *", 2),
            ("le16", 2),
            ("le16 *", 2),
            ("u32", 4),
            ("u32 *", 4),
            ("s32", 4),
            ("s32 *", 4),
            ("be32", 4),
            ("be32 *", 4),
            ("le32", 4),
            ("le32 *", 4),
            ("u64", 8),
            ("u64 *", 8),
            ("s64", 8),
            ("s64 *", 8),
            ("be64", 8),
            ("be64 *", 8),
            ("le64", 8),
            ("le64 *", 8),
            ("short", 2),
            ("short *", 2),
            ("unsigned short", 2),
            ("int", 4),
            ("int *", 4),
            ("unsigned int", 4),
            ("unsigned", 4),
            ("long", 4), // Platform dependent, conservative estimate
            ("unsigned long", 4),
            ("long long", 8),
            ("unsigned long long", 8),
            ("float", 4),
            ("float *", 4),
            ("double", 8),
            ("double *", 8),
            ("long double", 16),
            ("void *", 1), // void* itself has no alignment, use 1
            ("unknown *", 1),
        ]
        .iter()
        .cloned()
        .collect();

        let normalized = self.normalize_type_for_alignment_lookup(type_str);

        // Check for exact match
        if let Some(&alignment) = alignments.get(normalized.as_str()) {
            return alignment;
        }

        // Check for struct types (typically at least 4-byte aligned)
        if normalized.starts_with("struct ") {
            return 4; // Conservative estimate for struct alignment
        }

        // For pointer types not in map, assume 4-byte alignment
        if normalized.ends_with("*") {
            return 4;
        }

        // Unknown types - return 0 to avoid false positives
        0
    }
}
