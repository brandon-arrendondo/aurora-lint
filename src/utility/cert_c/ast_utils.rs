// Common AST utilities for CERT C rules
// This module provides reusable functions for navigating and extracting information from the C AST

use lang_parsing_substrate::query;
use tree_sitter::Node;

// ============================================================================
// Node Text Extraction
// ============================================================================

/// Extract the text content of a node from the source code
pub fn get_node_text<'a>(node: &Node, source: &'a str) -> &'a str {
    query::node_text(*node, source.as_bytes())
}

/// Heuristic: does this call's name look like a custom deallocator
/// (destroy_*, free_*, delete_*, cleanup_*, release_*, close_*, or the
/// matching suffix forms)? Shared between MEM31-C's own custom-deallocator
/// handling and the prescan field-frees collector (`frees_param_fields`),
/// so a macro-wrapped free like `#define mosquitto_FREE(A) free(A)` is
/// recognized consistently in both places (task 2: MEM31-C ownership model —
/// sqc has no preprocessor, so such wrapper calls are otherwise invisible).
pub fn is_deallocation_call_name(func_name: &str) -> bool {
    if crate::analyze::macro_semantics::is_container_unlink_macro(func_name) {
        return false;
    }
    let lower_name = func_name.to_lowercase();
    lower_name.starts_with("destroy_")
        || lower_name.starts_with("free_")
        || lower_name.starts_with("delete_")
        || lower_name.starts_with("cleanup_")
        || lower_name.starts_with("release_")
        || lower_name.starts_with("close_")
        || lower_name.ends_with("_destroy")
        || lower_name.ends_with("_free")
        || lower_name.ends_with("_delete")
        || lower_name.ends_with("_cleanup")
        || lower_name.ends_with("_release")
        || lower_name.ends_with("_close")
}

/// Extract the text content of a node as an owned String
pub fn get_node_text_owned(node: &Node, source: &str) -> String {
    query::node_text(*node, source.as_bytes()).to_string()
}

/// Extract a node's text with comment, string-literal, and char-literal spans
/// blanked out (replaced with spaces, preserving byte offsets/length).
///
/// For rules whose heuristics are too intricate to safely re-derive as pure
/// AST structural checks, this lets an existing text-substring heuristic run
/// against sanitized text instead — so a `.contains("UINT_MAX")` or similar
/// pattern can no longer be spoofed by a comment or string literal elsewhere
/// in the scanned span (a real false-negative risk: silent suppression of a
/// genuine violation, which is the worse failure direction for a security tool).
pub fn get_sanitized_node_text(node: &Node, source: &str) -> String {
    let start = node.start_byte();
    let end = node.end_byte();
    let mut bytes = source.as_bytes()[start..end].to_vec();
    for lit in
        query::find_descendants_of_kinds(*node, &["comment", "string_literal", "char_literal"])
    {
        let lit_start = lit.start_byte().max(start);
        let lit_end = lit.end_byte().min(end);
        if lit_start < lit_end {
            // Blank every byte except embedded newlines, so a multi-line
            // comment/string doesn't collapse onto one line — callers that
            // scan sanitized text line-by-line (`.lines()`) rely on the
            // original line structure being preserved.
            for b in &mut bytes[(lit_start - start)..(lit_end - start)] {
                if *b != b'\n' {
                    *b = b' ';
                }
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

// ============================================================================
// AST Navigation
// ============================================================================

/// Find the containing function definition for a given node
/// Returns the function_definition node that contains the given node
pub fn find_containing_function<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "function_definition" {
        return Some(*node);
    }
    query::nearest_ancestor_of_kind(*node, "function_definition")
}

/// Walk up from `ident_node` through enclosing `compound_statement` blocks to
/// find the nearest `declaration` that binds `name`, preferring the latest
/// (highest byte offset) such declaration before `ident_node`'s own position
/// within each block. Correctly disambiguates shadowed re-declarations of the
/// same name in sibling or nested blocks — unlike a whole-function text/regex
/// scan, which cannot tell two different declarations of the same identifier
/// apart.
///
/// Stops at the function body (does not resolve to a parameter — callers
/// needing that should also check `is_function_parameter` separately).
pub fn find_enclosing_declaration_for_identifier<'a>(
    ident_node: &Node<'a>,
    name: &str,
    source: &str,
) -> Option<Node<'a>> {
    let mut search_from = *ident_node;
    loop {
        let block = query::find_ancestor(search_from, |n| n.kind() == "compound_statement")?;
        let mut best: Option<Node<'a>> = None;
        for i in 0..block.child_count() {
            let Some(child) = block.child(i) else {
                continue;
            };
            if child.kind() == "declaration"
                && child.start_byte() < ident_node.start_byte()
                && declaration_binds_name(&child, name, source)
                && best.is_none_or(|b: Node<'a>| child.start_byte() > b.start_byte())
            {
                best = Some(child);
            }
        }
        if best.is_some() {
            return best;
        }
        search_from = block;
    }
}

/// True if a `declaration` node binds `name` via a direct declarator (`T
/// name;`) or an `init_declarator` (`T name = value;`), including
/// comma-separated multi-declarator declarations.
fn declaration_binds_name(decl_node: &Node, name: &str, source: &str) -> bool {
    for i in 0..decl_node.child_count() {
        let Some(child) = decl_node.child(i) else {
            continue;
        };
        let declarator = match child.kind() {
            "init_declarator" => child.child_by_field_name("declarator").unwrap_or(child),
            "identifier" | "pointer_declarator" | "array_declarator" | "function_declarator" => {
                child
            }
            _ => continue,
        };
        if get_identifier_from_declarator(&declarator, source) == name {
            return true;
        }
    }
    false
}

/// Fallback for file-scope (global) declarations, which
/// `find_enclosing_declaration_for_identifier` intentionally does not
/// resolve to (it only walks enclosing `compound_statement` blocks).
/// Restricted to direct children of the translation unit so it can't cross
/// into an unrelated function body.
///
/// This generalizes a scan that MSC05-C, MSC15-C, and CON34-C each
/// hand-rolled independently (task 387 item #3) as a type- or
/// qualifier-filtered variant of the same walk.
pub fn find_global_declaration_for_identifier<'a>(
    ident_node: &Node<'a>,
    name: &str,
    source: &str,
) -> Option<Node<'a>> {
    let mut top = *ident_node;
    while let Some(p) = top.parent() {
        top = p;
    }
    (0..top.child_count())
        .filter_map(|i| top.child(i))
        .find(|decl| decl.kind() == "declaration" && declaration_binds_name(decl, name, source))
}

/// Where an identifier use resolves to its binding declaration/parameter.
pub enum IdentifierBinding<'a> {
    /// Bound by a local (block-scope) declaration.
    Local(Node<'a>),
    /// Bound by a function parameter; carries the parameter's type text
    /// since a parameter has no `declaration` node of its own to point at.
    Parameter(String),
    /// Bound by a file-scope (translation-unit level) declaration.
    Global(Node<'a>),
}

/// Resolve `ident_node` (an occurrence of `name`) to wherever it's bound:
/// the nearest enclosing local declaration, else the containing function's
/// parameter list, else a file-scope global declaration. Chains
/// [`find_enclosing_declaration_for_identifier`], [`get_function_parameters`],
/// and [`find_global_declaration_for_identifier`] in that order so callers
/// don't each hand-roll the same 3-way fallback (task 387 item #3 -- MSC05-C,
/// MSC15-C, FIO34-C, ENV34-C, INT34-C, and CON34-C all did this
/// independently).
pub fn resolve_identifier_binding<'a>(
    ident_node: &Node<'a>,
    name: &str,
    source: &str,
) -> Option<IdentifierBinding<'a>> {
    if let Some(decl) = find_enclosing_declaration_for_identifier(ident_node, name, source) {
        return Some(IdentifierBinding::Local(decl));
    }
    if let Some(func) = find_containing_function(ident_node) {
        if let Some(params) = get_function_parameters(&func, source) {
            if let Some((_, ptype)) = params.iter().find(|(n, _)| n == name) {
                return Some(IdentifierBinding::Parameter(ptype.clone()));
            }
        }
    }
    find_global_declaration_for_identifier(ident_node, name, source).map(IdentifierBinding::Global)
}

/// Extract the type text (tokens before the declarator) of a `declaration`
/// node, e.g. `time_t x;` -> `"time_t"`, `static unsigned int x;` ->
/// `"static unsigned int"`.
fn declaration_type_text(decl: &Node, source: &str) -> String {
    (0..decl.child_count())
        .filter_map(|i| decl.child(i))
        .take_while(|c| {
            !matches!(
                c.kind(),
                "identifier" | "init_declarator" | "pointer_declarator" | "array_declarator"
            )
        })
        .map(|c| get_node_text(&c, source))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Convenience wrapper over [`resolve_identifier_binding`] for callers that
/// only need the resolved type text, not the binding site itself.
pub fn resolve_identifier_type(ident_node: &Node, name: &str, source: &str) -> Option<String> {
    match resolve_identifier_binding(ident_node, name, source)? {
        IdentifierBinding::Local(decl) | IdentifierBinding::Global(decl) => {
            Some(declaration_type_text(&decl, source))
        }
        IdentifierBinding::Parameter(ptype) => Some(ptype),
    }
}

/// Check if a node is inside a loop (for, while, or do-while)
///
/// No function-boundary short-circuit: `function_definition`s never nest in
/// C, so walking past one to check outer scopes can't happen in practice —
/// same result as the boundary-stopping version, one predicate instead of two.
pub fn is_inside_loop(node: &Node) -> bool {
    query::find_ancestor(*node, |n| {
        matches!(
            n.kind(),
            "for_statement" | "while_statement" | "do_statement"
        )
    })
    .is_some()
}

/// Check if a node is inside a conditional statement (if, else if, switch)
#[allow(dead_code)]
pub fn is_inside_conditional(node: &Node) -> bool {
    query::find_ancestor(*node, |n| {
        matches!(n.kind(), "if_statement" | "switch_statement")
    })
    .is_some()
}

// ============================================================================
// Identifier Extraction from Declarators
// ============================================================================

/// Extract identifier name from a declarator node
/// Handles simple identifiers, pointer declarators, and array declarators
///
/// Examples:
/// - int x           -> "x"
/// - int *ptr        -> "ptr"
/// - int arr[10]     -> "arr"
/// - int **ptr       -> "ptr"
/// - int (*fn)(int)  -> "fn"
pub fn get_identifier_from_declarator(declarator: &Node, source: &str) -> String {
    match declarator.kind() {
        "identifier" => get_node_text_owned(declarator, source),
        "pointer_declarator"
        | "array_declarator"
        | "function_declarator"
        | "parenthesized_declarator" => {
            // Recursively search for the identifier
            for i in 0..declarator.child_count() {
                if let Some(child) = declarator.child(i) {
                    if child.kind() == "identifier" {
                        return get_node_text_owned(&child, source);
                    }
                    let nested = get_identifier_from_declarator(&child, source);
                    if !nested.is_empty() {
                        return nested;
                    }
                }
            }
            String::new() // Return empty string for consistency with original implementations
        }
        _ => String::new(), // Return empty string for consistency with original implementations
    }
}

/// Find identifier in a declarator node, returns Option instead of "unknown" string.
///
/// Delegates to [`get_identifier_from_declarator`], which (unlike this
/// function's original implementation) checks the declarator's own node kind
/// before scanning its children — needed for a bare, unwrapped declarator
/// (`int j = 0;`) where the declarator field IS the identifier directly.
/// The old children-only scan returned `None` for that shape, which caused a
/// live regression in CON34-C's OpenMP shared-variable detection (task 385).
pub fn find_identifier_in_declarator(declarator: &Node, source: &str) -> Option<String> {
    let name = get_identifier_from_declarator(declarator, source);
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

// ============================================================================
// Function Parameter Extraction
// ============================================================================

/// Extract function parameters as (name, full_type) tuples
/// Returns None if the function has no parameters or parameter list not found
pub fn get_function_parameters(
    function_node: &Node,
    source: &str,
) -> Option<Vec<(String, String)>> {
    let declarator = find_function_declarator(function_node)?;
    extract_parameters(&declarator, source)
}

/// Find the `function_declarator` in a function's declarator subtree. For a
/// function returning a non-pointer type it is a direct child of the
/// `function_definition`; for a pointer-returning function (`char *
/// name(...)`) it is nested one level deeper inside a `pointer_declarator`,
/// which the previous direct-children-only scan missed entirely.
fn find_function_declarator<'a>(function_node: &Node<'a>) -> Option<Node<'a>> {
    for i in 0..function_node.child_count() {
        let child = function_node.child(i)?;
        match child.kind() {
            "function_declarator" => return Some(child),
            "pointer_declarator" => {
                if let Some(found) = find_function_declarator(&child) {
                    return Some(found);
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract parameters from a function declarator node
fn extract_parameters(declarator_node: &Node, source: &str) -> Option<Vec<(String, String)>> {
    let mut parameters = Vec::new();

    // Find parameter_list node
    for i in 0..declarator_node.child_count() {
        if let Some(child) = declarator_node.child(i) {
            if child.kind() == "parameter_list" {
                // Extract each parameter
                for j in 0..child.child_count() {
                    if let Some(param) = child.child(j) {
                        if param.kind() == "parameter_declaration" {
                            if let Some((name, param_type)) = extract_parameter_info(&param, source)
                            {
                                parameters.push((name, param_type));
                            }
                        }
                    }
                }
            }
        }
    }

    if parameters.is_empty() {
        None
    } else {
        Some(parameters)
    }
}

/// Extract parameter information (name and type) from a parameter declaration
fn extract_parameter_info(param_node: &Node, source: &str) -> Option<(String, String)> {
    let param_text = get_node_text(param_node, source);

    // Look for declarator pattern
    for i in 0..param_node.child_count() {
        if let Some(child) = param_node.child(i) {
            if matches!(
                child.kind(),
                "array_declarator" | "pointer_declarator" | "function_declarator"
            ) {
                // Found array, pointer, or function pointer parameter
                if let Some(identifier) = find_identifier_in_declarator(&child, source) {
                    return Some((identifier, param_text.to_string()));
                }
            } else if child.kind() == "identifier" {
                // Simple parameter
                let name = get_node_text(&child, source);
                return Some((name.to_string(), param_text.to_string()));
            }
        }
    }

    None
}

/// Check if a variable name appears in the function's parameter list
pub fn is_function_parameter(function_node: &Node, var_name: &str, source: &str) -> bool {
    // Find parameter list in function
    for i in 0..function_node.child_count() {
        if let Some(child) = function_node.child(i) {
            if child.kind() == "function_declarator" {
                for j in 0..child.child_count() {
                    if let Some(param_list) = child.child(j) {
                        if param_list.kind() == "parameter_list" {
                            let param_text = get_node_text(&param_list, source);
                            // Check for word boundaries to avoid substring matches
                            let words: Vec<&str> = param_text
                                .split(|c: char| !c.is_alphanumeric() && c != '_')
                                .collect();
                            if words.contains(&var_name) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

// ============================================================================
// Type Checking Utilities
// ============================================================================

/// Check if a parameter type string indicates an array parameter
pub fn is_array_parameter_type(param_type: &str) -> bool {
    param_type.contains('[') || (param_type.contains('*') && !param_type.contains("const char *"))
}

/// Check if a type string represents a pointer type
pub fn is_pointer_type(type_str: &str) -> bool {
    type_str.contains('*')
}

/// Check if a type string represents a generic (non-pointer-storage) integer
/// type: `int`/`unsigned`/`long`/`short`/`char`/`size_t`/`ptrdiff_t`, but NOT
/// `uintptr_t`/`intptr_t` (those are pointer-storage-safe integer types, a
/// distinct concept from "is this an integer at all").
pub fn is_integer_type(type_str: &str) -> bool {
    const INTEGER_TYPES: &[&str] = &[
        "int",
        "unsigned",
        "long",
        "short",
        "char",
        "size_t",
        "ptrdiff_t",
    ];
    INTEGER_TYPES.iter().any(|&t| {
        type_str.contains(t) && !type_str.contains("uintptr_t") && !type_str.contains("intptr_t")
    })
}

/// Check if a type string represents a signed integer type
#[allow(dead_code)]
pub fn is_signed_type(type_str: &str) -> bool {
    matches!(
        type_str.trim(),
        "int"
            | "short"
            | "long"
            | "char"
            | "signed"
            | "signed int"
            | "signed short"
            | "signed long"
            | "long long"
            | "signed long long"
            | "signed char"
            | "int8_t"
            | "int16_t"
            | "int32_t"
            | "int64_t"
            | "ptrdiff_t"
            | "ssize_t"
    )
}

/// Check if a type string represents an unsigned integer type
#[allow(dead_code)]
pub fn is_unsigned_type(type_str: &str) -> bool {
    type_str.contains("unsigned")
        || matches!(
            type_str.trim(),
            "size_t" | "uint8_t" | "uint16_t" | "uint32_t" | "uint64_t" | "uintptr_t" | "uintmax_t"
        )
}

// ============================================================================
// Operator Extraction
// ============================================================================

/// Extract the operator from a binary expression node
pub fn get_binary_operator<'a>(node: &Node, source: &'a str) -> Option<&'a str> {
    // The operator is usually a child of the binary expression
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let kind = child.kind();
            // Check if this is an operator token
            if matches!(
                kind,
                "+" | "-"
                    | "*"
                    | "/"
                    | "%"
                    | "=="
                    | "!="
                    | "<"
                    | ">"
                    | "<="
                    | ">="
                    | "&&"
                    | "||"
                    | "&"
                    | "|"
                    | "^"
                    | "<<"
                    | ">>"
                    | "="
                    | "+="
                    | "-="
                    | "*="
                    | "/="
                    | "%="
                    | "&="
                    | "|="
                    | "^="
                    | "<<="
                    | ">>="
            ) {
                return Some(get_node_text(&child, source));
            }
        }
    }
    None
}

// ============================================================================
// Array Size Extraction
// ============================================================================

/// Find array size from declaration in preceding text
/// Looks for patterns like: type array_name[size]
/// Returns the size if found and it's a constant
#[allow(dead_code)]
pub fn find_array_size(array_name: &str, preceding_text: &str) -> Option<usize> {
    // Look for array declaration pattern: array_name[number]
    let pattern = format!("{}[", array_name);

    if let Some(pos) = preceding_text.rfind(&pattern) {
        // Extract the size between [ and ]
        let after_bracket = &preceding_text[pos + pattern.len()..];
        if let Some(close_bracket) = after_bracket.find(']') {
            let size_str = after_bracket[..close_bracket].trim();

            // Try to parse as a number
            if let Ok(size) = size_str.parse::<usize>() {
                return Some(size);
            }

            // Try to handle simple arithmetic expressions like 2*3 or 10+5
            if size_str.contains('*') {
                let parts: Vec<&str> = size_str.split('*').collect();
                if parts.len() == 2 {
                    if let (Ok(a), Ok(b)) = (
                        parts[0].trim().parse::<usize>(),
                        parts[1].trim().parse::<usize>(),
                    ) {
                        return Some(a * b);
                    }
                }
            }
        }
    }

    None
}

/// Get the size of a C type in bytes
/// This is a best-effort approximation for common types
#[allow(dead_code)]
pub fn get_type_size(type_name: &str) -> usize {
    match type_name.trim() {
        "char" | "signed char" | "unsigned char" | "int8_t" | "uint8_t" => 1,
        "short" | "signed short" | "unsigned short" | "int16_t" | "uint16_t" => 2,
        "int" | "signed int" | "unsigned int" | "int32_t" | "uint32_t" | "float" => 4,
        "long" | "signed long" | "unsigned long" | "long long" | "signed long long"
        | "unsigned long long" | "int64_t" | "uint64_t" | "double" | "size_t" | "ptrdiff_t" => 8,
        "long double" => 16,
        t if t.ends_with('*') => 8, // Pointer size on 64-bit
        _ => 4,                     // Default to int size
    }
}

// ============================================================================
// Context Analysis
// ============================================================================

/// Check if a subscript expression is on the left side of an assignment (write context)
/// Handles nested subscripts like matrix[i][j] = value
pub fn is_write_context(node: &Node) -> bool {
    let mut current = *node;

    // Walk up the tree while we're in subscript expressions
    loop {
        if let Some(parent) = current.parent() {
            if parent.kind() == "assignment_expression" {
                // Check if current node (or its ancestor subscript) is the left side
                if let Some(left) = parent.child_by_field_name("left") {
                    return left.id() == current.id();
                }
                return false;
            } else if parent.kind() == "subscript_expression" {
                // Keep walking up through nested subscripts
                current = parent;
            } else {
                // Hit a different node type, not a write context
                return false;
            }
        } else {
            // No parent, not a write context
            return false;
        }
    }
}

/// Check if a node is part of a sizeof expression
#[allow(dead_code)]
pub fn is_in_sizeof(node: &Node) -> bool {
    query::nearest_ancestor_of_kind(*node, "sizeof_expression").is_some()
}

// ============================================================================
// Control Flow Navigation Utilities
// ============================================================================

/// Find the containing for loop statement for a given node
///
/// # Arguments
/// * `node` - The starting node to search from
///
/// # Returns
/// The for_statement node that contains the given node, or None if not found
///
/// # Examples
/// ```no_run
/// use sqc::utility::cert_c::ast_utils::find_containing_for_loop;
/// use tree_sitter::Node;
/// // When checking a subscript inside a for loop:
/// // let subscript_node: Node = /* get from parsed AST */;
/// // if let Some(for_loop) = find_containing_for_loop(&subscript_node) {
/// //     // Analyze loop bounds
/// // }
/// ```
pub fn find_containing_for_loop<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    query::nearest_ancestor_of_kind(*node, "for_statement")
}

/// Find the containing if statement for a given node
///
/// # Arguments
/// * `node` - The starting node to search from
///
/// # Returns
/// The if_statement node that contains the given node, or None if not found
///
/// # Examples
/// ```no_run
/// use sqc::utility::cert_c::ast_utils::find_containing_if_statement;
/// use tree_sitter::Node;
/// // When checking if array access is within a bounds check:
/// // let subscript_node: Node = /* get from parsed AST */;
/// // if let Some(if_stmt) = find_containing_if_statement(&subscript_node) {
/// //     // Check if condition validates bounds
/// // }
/// ```
pub fn find_containing_if_statement<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    query::nearest_ancestor_of_kind(*node, "if_statement")
}

// ============================================================================
// Struct Type Resolution
// ============================================================================

/// Extract the struct name from a C type string.
///
/// Handles patterns like:
/// - `"struct MyStruct *"` → `Some("MyStruct")`
/// - `"struct MyStruct"` → `Some("MyStruct")`
/// - `"MyStruct *"` → `Some("MyStruct")`
/// - `"MyStruct"` → `Some("MyStruct")`
/// - `"int"` → `None` (primitive type, not a struct)
///
/// For typedef'd structs (e.g., `typedef struct Foo { ... } Foo;`), the
/// type_map entry may be just `"Foo *"` without the `struct` keyword.
pub fn extract_struct_name_from_type(type_str: &str) -> Option<&str> {
    let trimmed = type_str.trim();

    // Strip pointer/const/volatile qualifiers from both ends
    let mut base = trimmed
        .trim_end_matches('*')
        .trim_end()
        .trim_end_matches("const")
        .trim_end_matches("volatile")
        .trim();
    loop {
        let next = base
            .strip_prefix("const ")
            .or_else(|| base.strip_prefix("volatile "))
            .unwrap_or(base)
            .trim();
        if next == base {
            break;
        }
        base = next;
    }

    // Skip obvious primitives
    if matches!(
        base,
        "int"
            | "unsigned int"
            | "signed int"
            | "short"
            | "unsigned short"
            | "long"
            | "unsigned long"
            | "long long"
            | "unsigned long long"
            | "char"
            | "unsigned char"
            | "signed char"
            | "float"
            | "double"
            | "void"
            | "_Bool"
    ) {
        return None;
    }
    // Skip stdint types
    if base.ends_with("_t")
        && (base.starts_with("int") || base.starts_with("uint") || base.starts_with("size"))
    {
        return None;
    }

    // "struct MyStruct" → "MyStruct"
    if let Some(name) = base.strip_prefix("struct ") {
        let name = name.trim();
        if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Some(name);
        }
        return None;
    }

    // Bare identifier (typedef'd name) — must look like an identifier, not a primitive
    if !base.is_empty()
        && base
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
        && base.chars().all(|c| c.is_alphanumeric() || c == '_')
    {
        return Some(base);
    }

    None
}

/// Resolve the type of a `field_expression` node using the variable type map
/// and struct field type database.
///
/// Given `s->count` where `s` is declared as `struct MyStruct *s`:
/// 1. Extracts field name "count" from the field_expression
/// 2. Looks up base variable "s" → "struct MyStruct *" in type_map
/// 3. Extracts struct name "MyStruct"
/// 4. Looks up "MyStruct"."count" → "int" in struct_field_types
pub fn resolve_field_expression_type(
    node: &Node,
    source: &str,
    type_map: &std::collections::HashMap<String, String>,
    struct_field_types: &std::collections::HashMap<
        String,
        std::collections::HashMap<String, String>,
    >,
) -> Option<String> {
    let field_node = node.child_by_field_name("field")?;
    let field_name = field_node.utf8_text(source.as_bytes()).ok()?;
    let argument = node.child_by_field_name("argument")?;

    // Resolve the struct type of the argument. Supports chained access
    // (`a.b.c`, `a->b.c`) by recursing through nested field_expressions.
    let base_type = match argument.kind() {
        "identifier" => {
            let base_name = argument.utf8_text(source.as_bytes()).ok()?;
            type_map.get(base_name)?.clone()
        }
        "field_expression" => {
            resolve_field_expression_type(&argument, source, type_map, struct_field_types)?
        }
        "pointer_expression" => {
            // `*p.field` — dereference one pointer level from `p`'s type.
            let inner = argument.child_by_field_name("argument")?;
            let inner_name = inner.utf8_text(source.as_bytes()).ok()?;
            let t = type_map.get(inner_name)?;
            t.strip_suffix(" *")
                .or_else(|| t.strip_suffix('*'))
                .map(|s| s.trim().to_string())?
        }
        _ => return None,
    };

    let struct_name = extract_struct_name_from_type(&base_type)?;

    struct_field_types
        .get(struct_name)
        .and_then(|fields| fields.get(field_name))
        .cloned()
}

/// Result of inspecting a `struct_specifier` for packed-ness.
pub enum PackedSignal {
    /// Not packed (or no signal found).
    No,
    /// Directly `__attribute__((packed))` on the specifier — resolved
    /// without needing any other file's context.
    Direct,
    /// A trailing bare identifier between the closing brace and the
    /// terminating `;`/field name (e.g. `struct foo { ... } STRUCT_PACKED;`)
    /// that *might* be a packed-attribute macro — its `#define` may live in
    /// a different file (a header this one doesn't textually include in
    /// sqc's no-preprocessor model), so the caller must resolve the name
    /// against a project-wide macro-name set.
    MacroCandidate(String),
}

/// Inspect `struct_specifier` (a struct *definition*, with a body) for a
/// packed-attribute signal. Some C parsers have no preprocessor, so a
/// trailing macro token like hostap's `STRUCT_PACKED` gets parsed as if it
/// were a declarator/field name rather than an attribute — the caller
/// resolves that candidate name against `#define`s collected project-wide
/// (see `macro_expands_to_packed`), which keeps this codebase-independent
/// rather than a hardcoded name heuristic.
pub fn struct_specifier_packed_signal(s: &Node, source: &str) -> PackedSignal {
    for attr in query::find_descendants_of_kind(*s, "attribute_specifier") {
        if get_node_text(&attr, source).contains("packed") {
            return PackedSignal::Direct;
        }
    }
    let Some(parent) = s.parent() else {
        return PackedSignal::No;
    };
    if !matches!(
        parent.kind(),
        "declaration" | "field_declaration" | "type_definition"
    ) {
        return PackedSignal::No;
    }
    let parent_text = get_node_text(&parent, source);
    let struct_text = get_node_text(s, source);
    let Some(tail) = parent_text.strip_prefix(struct_text) else {
        return PackedSignal::No;
    };
    let Ok(ident_re) = regex::Regex::new(r"[A-Za-z_][A-Za-z0-9_]*") else {
        return PackedSignal::No;
    };
    match ident_re.find(tail) {
        Some(m) => PackedSignal::MacroCandidate(m.as_str().to_string()),
        None => PackedSignal::No,
    }
}

/// True if `struct_specifier` is packed, resolving any trailing-macro
/// candidate against `#define`s in this SAME `source` text only. Used by
/// the single-file/intra-file prescan path (test fixtures); the cross-file
/// prescan path resolves `MacroCandidate`s against a project-wide macro-name
/// set instead (see `analyze::prescan::collect_packed_structs`).
pub fn struct_specifier_is_packed(s: &Node, source: &str) -> bool {
    match struct_specifier_packed_signal(s, source) {
        PackedSignal::Direct => true,
        PackedSignal::MacroCandidate(name) => macro_expands_to_packed(&name, source),
        PackedSignal::No => false,
    }
}

/// True if `#define name ...` appears in `source` and its replacement text
/// contains "packed" (e.g. `#define STRUCT_PACKED __attribute__
/// ((packed))`).
pub fn macro_expands_to_packed(name: &str, source: &str) -> bool {
    let Ok(re) = regex::Regex::new(&format!(
        r"(?m)^\s*#\s*define\s+{}\b.*$",
        regex::escape(name)
    )) else {
        return false;
    };
    re.find(source)
        .map(|m| m.as_str().contains("packed"))
        .unwrap_or(false)
}

/// Collect every `#define NAME ...` object-macro name in `source` whose
/// replacement text contains "packed" (e.g. hostap's `#define STRUCT_PACKED
/// __attribute__ ((packed))`). Plain regex over raw text, not AST-based —
/// deliberately independent of any single file's struct definitions so it
/// can be merged project-wide and used to resolve `PackedSignal::MacroCandidate`s
/// found in *other* files.
pub fn collect_packed_macro_names(source: &str, out: &mut std::collections::HashSet<String>) {
    let Ok(re) = regex::Regex::new(r"(?m)^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b.*$") else {
        return;
    };
    for cap in re.captures_iter(source) {
        let line = cap.get(0).map(|m| m.as_str()).unwrap_or("");
        if line.contains("packed") {
            if let Some(name) = cap.get(1) {
                out.insert(name.as_str().to_string());
            }
        }
    }
}

/// True if `#define name ...` appears anywhere in `source`, regardless of
/// what it expands to. Used to recognize a trailing bare identifier right
/// after a struct/union/enum body (e.g. `struct foo { ... } SOME_MACRO;`) as
/// an attribute-position macro invocation rather than a genuine object
/// declaration: sqc has no preprocessor, so such a macro is parsed as if it
/// were the declared object's name, but a real C identifier can never
/// collide with an in-scope `#define` name (the preprocessor would have
/// substituted it first) — so if the name is a known macro, this can't be a
/// real declaration (DCL40-C task 432).
pub fn is_defined_macro_name(name: &str, source: &str) -> bool {
    let Ok(re) = regex::Regex::new(&format!(r"(?m)^\s*#\s*define\s+{}\b", regex::escape(name)))
    else {
        return false;
    };
    re.is_match(source)
}

/// True if `name` looks like a preprocessor macro constant *by naming
/// convention alone*: ALL_CAPS letters, digits and underscores only, and not
/// starting with a digit (so a bare numeric literal is never mistaken for a
/// macro name). Empty input is never a macro name.
///
/// This never consults an actual `#define` — prefer
/// `is_defined_macro_name` (or `ProjectContext`'s project-wide macro-name
/// set) whenever the definition is reachable, and prefer
/// `analyze::macro_expand` whenever the macro's *value* matters. This is the
/// last-resort guess for "is this identifier a compile-time constant?" when
/// no definition is in scope — e.g. distinguishing `int a[SIZE]` (not a VLA)
/// from `int a[n]` (a VLA).
///
/// Single source of truth for a heuristic that was independently
/// reimplemented in five rules with slightly different edge cases
/// (task 603): MEM05-C, ARR32-C, MEM33-C, DCL03-C, EXP08-C.
///
/// # Examples
/// ```
/// use sqc::utility::cert_c::ast_utils::is_likely_macro_constant;
/// assert!(is_likely_macro_constant("MAX_SIZE"));
/// assert!(is_likely_macro_constant("_BUF_LEN2"));
/// assert!(!is_likely_macro_constant("bufLen"));
/// assert!(!is_likely_macro_constant("10"));
/// assert!(!is_likely_macro_constant(""));
/// ```
pub fn is_likely_macro_constant(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
}

/// Collect every `#define NAME ...` object-macro name in `source`,
/// regardless of what it expands to. Plain regex over raw text, not
/// AST-based — deliberately independent of any single file's declarations
/// so it can be merged project-wide and used to resolve a trailing bare
/// identifier found in *other* files against the macro's actual `#define`
/// (which commonly lives in a different header, e.g. hostap's
/// `STRUCT_PACKED` in `utils/common.h` vs. structs in
/// `common/ieee802_11_defs.h`). Generalizes `collect_packed_macro_names` to
/// any macro name, not just packed-attribute ones — see `is_defined_macro_name`.
pub fn collect_defined_macro_names(source: &str, out: &mut std::collections::HashSet<String>) {
    let Ok(re) = regex::Regex::new(r"(?m)^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b") else {
        return;
    };
    for cap in re.captures_iter(source) {
        if let Some(name) = cap.get(1) {
            out.insert(name.as_str().to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_c_code(code: &str) -> (tree_sitter::Tree, String) {
        let mut parser = Parser::new();
        let language = crate::parser::c_language();
        parser.set_language(&language).unwrap();
        let tree = parser.parse(code, None).unwrap();
        (tree, code.to_string())
    }

    #[test]
    fn test_get_node_text() {
        let (tree, source) = parse_c_code("int x = 5;");
        let root = tree.root_node();
        let text = get_node_text(&root, &source);
        assert_eq!(text, "int x = 5;");
    }

    #[test]
    fn test_find_containing_function() {
        let (tree, _source) = parse_c_code("void foo() { int x = 5; }");
        let root = tree.root_node();

        // Find the declaration node (int x = 5)
        let func_def = root.child(0).unwrap();
        assert_eq!(func_def.kind(), "function_definition");

        // Find a node inside the function
        let compound_stmt = func_def.child_by_field_name("body").unwrap();
        let decl = compound_stmt.child(1).unwrap(); // Skip opening brace

        let containing_func = find_containing_function(&decl);
        assert!(containing_func.is_some());
        assert_eq!(containing_func.unwrap().kind(), "function_definition");
    }

    #[test]
    fn test_find_array_size() {
        let text = "int main() { int arr[10]; }";
        let size = find_array_size("arr", text);
        assert_eq!(size, Some(10));
    }

    #[test]
    fn test_is_signed_type() {
        assert!(is_signed_type("int"));
        assert!(is_signed_type("signed int"));
        assert!(is_signed_type("int32_t"));
        assert!(!is_signed_type("unsigned int"));
        assert!(!is_signed_type("size_t"));
    }

    #[test]
    fn test_is_unsigned_type() {
        assert!(is_unsigned_type("unsigned int"));
        assert!(is_unsigned_type("size_t"));
        assert!(is_unsigned_type("uint32_t"));
        assert!(!is_unsigned_type("int"));
        assert!(!is_unsigned_type("signed int"));
    }

    #[test]
    fn test_get_type_size() {
        assert_eq!(get_type_size("char"), 1);
        assert_eq!(get_type_size("short"), 2);
        assert_eq!(get_type_size("int"), 4);
        assert_eq!(get_type_size("long"), 8);
        assert_eq!(get_type_size("int *"), 8);
    }
}
