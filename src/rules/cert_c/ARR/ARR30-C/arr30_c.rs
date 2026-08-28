//! ARR30-C: Do not form or use out-of-bounds pointers or array subscripts
//!
//! This rule checker detects various patterns of out-of-bounds array access including:
//! - Static array bounds violations
//! - Dynamic allocation bounds violations
//! - Pointer arithmetic beyond buffer bounds
//! - Variable Length Array (VLA) violations
//! - Function parameter array access without bounds checking
//! - Recursive function array access
//! - Dangerous library function usage (strcpy, sprintf, gets, etc.)
//!
//! # Known Limitations
//!
//! ## Macro Expansion
//! This implementation partially supports C preprocessor macros:
//!
//! **Supported:**
//! - Macro constants in array size declarations are resolved:
//!   ```c
//!   #define SIZE 10
//!   int arr[SIZE];  // SIZE is resolved to 10
//!   ```
//!
//! **NOT Supported:**
//! - Function-like macros that generate array accesses are NOT expanded.
//!   These appear as function calls to the parser, not as array subscripts.
//!
//! Example that will NOT be detected:
//! ```c
//! #define UNSAFE_ACCESS(arr, idx) arr[idx + 5]
//! int data[8];
//! UNSAFE_ACCESS(data, 6);  // Parser sees a function call, not data[11]
//! ```
//!
//! Proper detection would require:
//! - Running the C preprocessor (cpp or clang -E) before parsing
//! - Mapping violations back to original source locations via #line directives
//!
//! This is a complex architectural change that may be added in future versions.

use super::super::{CertRule, RuleViolation};
use crate::analyze::buffer_size::{self, BufferInfo, BufferSize};
use crate::analyze::cfg::FunctionCfg;
use crate::analyze::const_eval::{self, VarRangeMap};
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::collect_param_names;
use crate::analyze::macro_expand::{collect_function_macros, FunctionMacro};
use crate::analyze::value_range::RangeAnalysisResult;
use crate::analyze::vra_access;
use crate::manifest::{RuleCategory, Severity};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

// Import shared utility functions
use crate::utility::cert_c::ast_utils::{
    find_containing_for_loop, find_containing_function, find_containing_if_statement,
    find_enclosing_declaration_for_identifier, find_identifier_in_declarator,
    get_identifier_from_declarator,
};
use crate::utility::cert_c::call_roles;

pub struct Arr30C {
    function_cfgs: RefCell<HashMap<usize, FunctionCfg>>,
    vra_results: RefCell<HashMap<usize, RangeAnalysisResult>>,
    /// Macro/enum/const constants gathered cross-file by the prescan
    /// (`context.macro_constants`). Merged with per-file constants so that
    /// buffer sizes defined in headers or other translation units resolve.
    macro_constants: RefCell<HashMap<String, i64>>,
    /// Per-function cache of blob/value-accessor-tainted pointer names, keyed by
    /// the function node's start byte. `check_unbounded_decode_loop` runs once
    /// per loop; memoizing keeps the taint scan O(functions) instead of
    /// O(loops × function size) on large real-world files. Cleared per file.
    decode_taint_cache: RefCell<HashMap<usize, HashSet<String>>>,
    /// Per-function cache of `const char *` / `const unsigned char *` parameter
    /// names (and their cast-aliases) that have no paired length parameter —
    /// candidate unbounded input buffers for the param-decoder index over-read
    /// family (task 210, sqlite `kvvfsDecode` class). Keyed by function start
    /// byte. Cleared per file.
    param_decode_buf_cache: RefCell<HashMap<usize, HashSet<String>>>,
    /// Function start bytes that already produced a param-decoder over-read
    /// finding, so nested loops in the same function don't each emit one. Cleared
    /// per file.
    param_decode_reported: RefCell<HashSet<usize>>,
    /// Per-translation-unit interprocedural over-read summary, keyed by function
    /// name: the positional indices of `const char *` parameters that the
    /// function walks unbounded (embedded-increment subscript with no length
    /// bound). Drives the task-211 callsite over-read detector, where the
    /// over-reading loop sits in a helper (`readUtf8(z, ...)`) and the caller
    /// passes a tainted pointer (+offset) with no length argument. Built once per
    /// file; `None` until the root pass populates it. Cleared per file.
    helper_overread_summary: RefCell<Option<HashMap<String, Vec<usize>>>>,
    /// File-scope-only buffer bindings (globals, struct/union member
    /// arrays, typedef-array members) — see `analyze_global_scope_buffers`.
    /// Computed once per file at the root `check()` call and used as the
    /// reset base for each function's own buffer tracking in
    /// `check_with_buffer_info`'s `function_definition` arm, so two
    /// functions with a same-named local buffer never conflate each
    /// other's size/allocation_line (task 389). Cleared per file.
    global_scope_buffers: RefCell<HashMap<String, BufferInfo>>,
    /// Typedef-array-size table for the current file (`analyze_typedefs`),
    /// cached alongside `global_scope_buffers` so re-scanning each
    /// function's own locals doesn't re-run the whole-file regex scan once
    /// per function. Cleared per file.
    cached_typedefs: RefCell<HashMap<String, usize>>,
}

/// Represents an index value that can be constant or variable
#[derive(Debug)]
#[allow(dead_code)]
enum IndexValue {
    Constant(isize),                   // Changed from usize to support negative indices
    Expression(String, Option<isize>), // Expression text and evaluated constant if possible
    Variable(String),
    Unknown,
}

/// Represents a pointer arithmetic offset
#[derive(Debug)]
#[allow(dead_code)]
enum OffsetValue {
    Constant(usize),
    Variable(String),
    Unknown,
}

/// Represents a pointer alias mapping
#[derive(Debug, Clone)]
struct PointerAlias {
    alias_name: String,      // The pointer variable name (e.g., "ptr", "int_array")
    original_buffer: String, // The original buffer name (e.g., "arr", "buffer")
    element_size_bytes: Option<usize>, // Element size for cast pointers (e.g., 4 for int, 1 for char)
}

/// Accessors that return a pointer into untrusted/binary data that is *not*
/// guaranteed to be NUL-terminated or length-validated at the call site.
/// Walking such a pointer in a decode loop without a dominating bound check is
/// an out-of-bounds read (task 172, the sqlite real-world ARR30 FN family of
/// varint / terminator-chase decode loops over column/blob bytes). Gating on a
/// blob/value accessor — rather than any `char *` — keeps the plain
/// NUL-terminated C-string walk idiom (`while (*s) s++;`) out of scope, since
/// that pointer is the caller's responsibility to terminate.
const UNTRUSTED_BLOB_ACCESSORS: &[&str] = &[
    "sqlite3_column_blob",
    "sqlite3_column_text",
    "sqlite3_column_text16",
    "sqlite3_value_blob",
    "sqlite3_value_text",
    "sqlite3_value_text16",
];

/// Varint readers that consume a bounded-but-unchecked run of continuation
/// bytes from a pointer. Called in a decode loop over an untrusted pointer with
/// no `p < end` guard, they over-read past the buffer (CERT ARR30-C).
const VARINT_READERS: &[&str] = &[
    "getVarint",
    "getVarint32",
    "sqlite3GetVarint",
    "sqlite3GetVarint32",
    "fts3GetVarint",
    "fts3GetVarint32",
    "fts5GetVarint",
    "fts5GetVarint32",
];

impl CertRule for Arr30C {
    fn rule_id(&self) -> &'static str {
        "ARR30-C"
    }

    fn description(&self) -> &'static str {
        "Do not form or use out-of-bounds pointers or array subscripts"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ARR30-C"
    }

    fn set_function_cfgs(&self, cfgs: &HashMap<usize, FunctionCfg>) {
        *self.function_cfgs.borrow_mut() = cfgs.clone();
    }

    fn set_vra_results(&self, results: &HashMap<usize, RangeAnalysisResult>) {
        *self.vra_results.borrow_mut() = results.clone();
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.macro_constants.borrow_mut() = context.macro_constants.clone();
    }

    fn needs_vra(&self) -> bool {
        true
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        // Analyze all buffer allocations once at root level
        if node.parent().is_none() {
            self.decode_taint_cache.borrow_mut().clear();
            self.param_decode_buf_cache.borrow_mut().clear();
            self.param_decode_reported.borrow_mut().clear();
            // Build the interprocedural over-read helper summary for this file
            // (task 211): function name -> indices of `const char *` params it
            // walks unbounded. Consumed by `check_overread_helper_callsite`.
            *self.helper_overread_summary.borrow_mut() =
                Some(self.build_helper_overread_summary(node, source));
            let mut buffer_info = self.analyze_buffer_allocations(source);
            let pointer_aliases = self.analyze_pointer_aliases(source, &buffer_info);
            // Task 389: the file-scope-only base each function's own buffer
            // tracking resets to in `check_with_buffer_info`'s
            // `function_definition` arm, plus the typedef table it's built
            // from, cached so it isn't recomputed per function.
            *self.global_scope_buffers.borrow_mut() = self.analyze_global_scope_buffers(source);
            *self.cached_typedefs.borrow_mut() = self.analyze_typedefs(source);
            // Shared file-local function-like macro collection
            // (`crate::analyze::macro_expand`) — replaces ARR30's former private
            // extractor. Same per-file scope; deletes a duplicate of the engine
            // used by MEM30/EXP33/DCL31.
            let function_macros = collect_function_macros(node, source);
            let flexible_array_structs = self.find_flexible_array_structs(node, source);

            // Task 554: a C99/struct-hack flexible array member's *declared*
            // size (often a literal `[1]` or empty `[]`) is a placeholder --
            // the real element count lives at whatever allocation reserves
            // `sizeof(struct X) + n * sizeof(elem)`-style extra space for it
            // (directly, or via a macro wrapping that expression). Once such
            // an allocation is found anywhere in the file, stop treating the
            // member's declared size as a hard bound: every access to it
            // was, until now, checked against the placeholder size and
            // flagged regardless of how the real (structurally correlated)
            // count was proven safe elsewhere -- 0% TP across 4 real-world
            // oracles (data/precision_audit/DELTA_ARR30_TASK537.md).
            let variable_sized_flexible_members = self.find_variable_sized_flexible_members(
                source,
                &flexible_array_structs,
                &function_macros,
            );
            for member in &variable_sized_flexible_members {
                if let Some(buf) = buffer_info.get_mut(member) {
                    buf.size = BufferSize::Unknown;
                }
                if let Some(buf) = self.global_scope_buffers.borrow_mut().get_mut(member) {
                    buf.size = BufferSize::Unknown;
                }
            }

            // Collect macro/enum/const constants for loop bound resolution
            let macro_constants = self.collect_constants(node, source);

            self.check_with_buffer_info(
                node,
                source,
                &buffer_info,
                &pointer_aliases,
                &function_macros,
                &flexible_array_structs,
                &macro_constants,
            )
        } else {
            // This shouldn't happen as we control recursion, but handle gracefully
            Vec::new()
        }
    }
}

impl Arr30C {
    pub fn new() -> Self {
        Self {
            function_cfgs: RefCell::new(HashMap::new()),
            vra_results: RefCell::new(HashMap::new()),
            macro_constants: RefCell::new(HashMap::new()),
            decode_taint_cache: RefCell::new(HashMap::new()),
            param_decode_buf_cache: RefCell::new(HashMap::new()),
            param_decode_reported: RefCell::new(HashSet::new()),
            helper_overread_summary: RefCell::new(None),
            global_scope_buffers: RefCell::new(HashMap::new()),
            cached_typedefs: RefCell::new(HashMap::new()),
        }
    }

    /// Collect compile-time integer constants for the current file: macro
    /// `#define`s, enums, and file-scope `[static] const` declarations, plus
    /// `<limits.h>`/`<stdint.h>` builtins. Uses the shared
    /// [`const_eval::collect_macro_constants`] (the same extractor that feeds
    /// the prescan context) rather than ARR30's former private parser, then
    /// merges in cross-file constants from the prescan (`set_project_context`)
    /// for names not defined in this file. Per-file definitions win.
    fn collect_constants(&self, root: &Node, source: &str) -> HashMap<String, i64> {
        const_eval::merged_macro_constants(&self.macro_constants.borrow(), root, source)
    }

    /// Get VRA-derived variable ranges at a specific expression node.
    fn vra_var_ranges_at(&self, expr_node: &Node) -> Option<VarRangeMap> {
        vra_access::var_ranges_entry_at(
            &self.function_cfgs.borrow(),
            &self.vra_results.borrow(),
            expr_node,
        )
    }

    /// Analyze all buffer allocations in the source code using AST traversal.
    ///
    /// This is a *whole-file, name-keyed* map: it deliberately also walks
    /// into every function body, so two different functions that happen to
    /// declare a same-named local buffer will conflate — whichever
    /// declaration is encountered last in source order wins the map entry.
    /// That's harmless for this map's one remaining purpose (feeding
    /// `analyze_pointer_aliases`, which only ever does an existence check —
    /// `buffers.contains_key(name)` — to decide whether an identifier is a
    /// *tracked buffer at all*, never reading its size or allocation_line).
    /// It is NOT safe to use for size/line-sensitive violation checks across
    /// function boundaries; see `analyze_global_scope_buffers` and its use
    /// in `check_with_buffer_info`'s `function_definition` arm (task 389).
    fn analyze_buffer_allocations(&self, source: &str) -> HashMap<String, BufferInfo> {
        let mut buffers = HashMap::new();

        // Parse the source code into AST
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&crate::parser::c_language())
            .expect("Error loading C grammar");

        let tree = match parser.parse(source, None) {
            Some(t) => t,
            None => return buffers,
        };

        let root_node = tree.root_node();

        // Collect macro/enum/const constants (shared const_eval extractor +
        // cross-file prescan constants) for resolving symbolic buffer sizes.
        let macros = self.collect_constants(&root_node, source);

        // Second pass: collect typedef information (still needed for typedef arrays)
        let typedefs = self.analyze_typedefs(source);

        // Analyze struct member arrays declared with typedefs
        self.analyze_struct_typedef_members(source, &typedefs, &mut buffers);

        // Traverse AST to find all declarations, including those nested in
        // function bodies.
        self.extract_buffers_from_ast(&root_node, source, &mut buffers, &typedefs, &macros, true);

        buffers
    }

    /// Like `analyze_buffer_allocations`, but scoped to *file scope only*:
    /// globals, struct/union member arrays, and typedef-array members —
    /// never a local declared inside a function body. This is the safe,
    /// collision-free base that every function starts its own buffer
    /// tracking from in `check_with_buffer_info`'s `function_definition`
    /// arm (task 389): each function then layers its own locals on top via
    /// a fresh `extract_buffers_from_ast` call scoped to just that
    /// function's body, so two functions with a same-named local buffer
    /// (different size, different declaration line) never see each other's
    /// entry.
    fn analyze_global_scope_buffers(&self, source: &str) -> HashMap<String, BufferInfo> {
        let mut buffers = HashMap::new();

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&crate::parser::c_language())
            .expect("Error loading C grammar");

        let tree = match parser.parse(source, None) {
            Some(t) => t,
            None => return buffers,
        };

        let root_node = tree.root_node();

        let macros = self.collect_constants(&root_node, source);
        let typedefs = self.analyze_typedefs(source);

        self.analyze_struct_typedef_members(source, &typedefs, &mut buffers);
        self.analyze_struct_field_array_buffers(
            &root_node,
            source,
            &typedefs,
            &macros,
            &mut buffers,
        );

        // `include_function_bodies = false`: do not descend into any
        // function_definition's body here.
        self.extract_buffers_from_ast(&root_node, source, &mut buffers, &typedefs, &macros, false);

        buffers
    }

    /// Track array-typed struct/union member fields (e.g. `Matrix
    /// stack[RL_MAX_MATRIX_STACK_SIZE];` inside a struct body) as buffers.
    ///
    /// `extract_buffers_from_ast` only walks top-level `declaration` nodes,
    /// but a struct member is a `field_declaration` node in tree-sitter-c's
    /// grammar -- a declaration directly inside a struct/union body was
    /// never seen at all, so an access like `RLGL.State.stack[idx]` had no
    /// buffer size to check against and silently produced no violation,
    /// regardless of whether `idx` was validated (task 235; real example:
    /// raylib's rlgl.h `RLGL.State.stack[RL_MAX_MATRIX_STACK_SIZE]`).
    /// `field_declaration` reuses the same declarator grammar as
    /// `declaration`, so the existing extractor works unmodified once
    /// pointed at the right node kind.
    fn analyze_struct_field_array_buffers(
        &self,
        root: &Node,
        source: &str,
        typedefs: &HashMap<String, usize>,
        macros: &HashMap<String, i64>,
        buffers: &mut HashMap<String, BufferInfo>,
    ) {
        for field in query::find_descendants_of_kind(*root, "field_declaration") {
            if let Some(mut buffer) =
                self.extract_buffer_from_declaration_with_typedefs(&field, source, typedefs)
            {
                if let BufferSize::Symbolic(ref sym) = buffer.size {
                    if let Some(&value) = macros.get(sym) {
                        buffer.size = BufferSize::Static(value as usize);
                    }
                }
                buffers.entry(buffer.name.clone()).or_insert(buffer);
            }
        }
    }

    /// Extract function-like macros from preprocessor directives
    /// Recursively extract buffer allocations from AST.
    ///
    /// `include_function_bodies` controls whether this descends into a
    /// `function_definition`'s body at all. Callers building the shared
    /// file-scope base (`analyze_global_scope_buffers`, task 389) pass
    /// `false` so function-local buffers from different functions never
    /// land in the same name-keyed map; callers that need every buffer in
    /// the file regardless of scope (`analyze_buffer_allocations`, whose
    /// only remaining consumer just does a name-existence check for
    /// pointer-alias detection) pass `true`.
    fn extract_buffers_from_ast(
        &self,
        node: &Node,
        source: &str,
        buffers: &mut HashMap<String, BufferInfo>,
        typedefs: &HashMap<String, usize>,
        macros: &HashMap<String, i64>,
        include_function_bodies: bool,
    ) {
        if !include_function_bodies && node.kind() == "function_definition" {
            return;
        }

        // Check if this node is a declaration
        if node.kind() == "declaration" {
            if let Some(mut buffer) =
                self.extract_buffer_from_declaration_with_typedefs(node, source, typedefs)
            {
                // Try to resolve macro constants in buffer size
                if let BufferSize::Symbolic(ref sym) = buffer.size {
                    if let Some(&value) = macros.get(sym) {
                        buffer.size = BufferSize::Static(value as usize);
                    }
                }

                // Handle realloc: keep existing buffer if it has smaller size
                if let Some(existing) = buffers.get(&buffer.name) {
                    match (&existing.size, &buffer.size) {
                        (
                            BufferSize::DynamicCalculated(old_size),
                            BufferSize::DynamicCalculated(new_size),
                        ) => {
                            if new_size < old_size {
                                buffers.insert(buffer.name.clone(), buffer.clone());
                            }
                        }
                        _ => {
                            buffers.insert(buffer.name.clone(), buffer.clone());
                        }
                    }
                } else {
                    buffers.insert(buffer.name.clone(), buffer.clone());
                }

                // For multidimensional arrays, extract inner dimensions
                self.extract_multidimensional_buffers(node, &buffer.name, source, buffers, macros);
            }

            // Also check for VLA declarations using typedef
            // VLAs need special handling as they may not be caught by AST alone
            if let Some(mut vla_buffer) = self.extract_vla_from_declaration(node, source, typedefs)
            {
                // Try to resolve macro constants in VLA buffer size
                if let BufferSize::Symbolic(ref sym) = vla_buffer.size {
                    if let Some(&value) = macros.get(sym) {
                        vla_buffer.size = BufferSize::Static(value as usize);
                    }
                }

                // Only insert if not already in map (prefer the already-resolved version)
                if !buffers.contains_key(&vla_buffer.name) {
                    buffers.insert(vla_buffer.name.clone(), vla_buffer);
                }
            }
        }

        // Check if this node is a struct_specifier or union_specifier to extract member arrays
        if node.kind() == "struct_specifier" || node.kind() == "union_specifier" {
            self.extract_struct_member_arrays(node, source, buffers);
        }

        // Check for assignment expressions with malloc (e.g., matrix[i] = malloc(...))
        // This handles dynamic allocations inside loops
        if node.kind() == "assignment_expression" || node.kind() == "expression_statement" {
            let assign_node = if node.kind() == "assignment_expression" {
                Some(*node)
            } else if node.kind() == "expression_statement" {
                // Look for assignment_expression child
                node.child(0)
                    .filter(|c| c.kind() == "assignment_expression")
            } else {
                None
            };

            if let Some(assign) = assign_node {
                if let Some((buf_name, buf_info)) =
                    self.extract_buffer_from_assignment(&assign, source)
                {
                    // Insert wildcard buffers from malloc assignments
                    buffers.insert(buf_name, buf_info);
                }
            }
        }

        // Recursively process children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.extract_buffers_from_ast(
                    &child,
                    source,
                    buffers,
                    typedefs,
                    macros,
                    include_function_bodies,
                );
            }
        }
    }

    /// Extract member arrays from struct_specifier or union_specifier node
    /// Handles patterns like:
    /// typedef struct {
    ///     char name[10];    // Extracts "name" with size 10
    ///     int scores[5];    // Extracts "scores" with size 5
    /// } Student;
    /// typedef union {
    ///     char bytes[4];    // Extracts "bytes" with size 4
    ///     int value;
    /// } Data;
    fn extract_struct_member_arrays(
        &self,
        node: &Node,
        source: &str,
        buffers: &mut HashMap<String, BufferInfo>,
    ) {
        // Find the field_declaration_list child node
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "field_declaration_list" {
                    // Process each field_declaration within the list
                    for j in 0..child.child_count() {
                        if let Some(field) = child.child(j) {
                            if field.kind() == "field_declaration" {
                                // Extract array member from field_declaration
                                if let Some(member_info) =
                                    self.extract_array_from_field_declaration(&field, source)
                                {
                                    buffers.insert(member_info.name.clone(), member_info);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Extract array information from a field_declaration node
    /// Handles patterns like: char name[10]; or int scores[5];
    fn extract_array_from_field_declaration(
        &self,
        node: &Node,
        source: &str,
    ) -> Option<BufferInfo> {
        // Look for array_declarator within the field_declaration
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "array_declarator" {
                    // Extract member name and size from array_declarator
                    let mut member_name: Option<String> = None;
                    let mut array_size: Option<usize> = None;

                    for j in 0..child.child_count() {
                        if let Some(declarator_child) = child.child(j) {
                            match declarator_child.kind() {
                                "field_identifier" => {
                                    // Struct member names use field_identifier
                                    member_name = Some(
                                        source[declarator_child.start_byte()
                                            ..declarator_child.end_byte()]
                                            .to_string(),
                                    );
                                }
                                "identifier" if j == 0 => {
                                    // Could also be a regular identifier in some cases
                                    member_name = Some(
                                        source[declarator_child.start_byte()
                                            ..declarator_child.end_byte()]
                                            .to_string(),
                                    );
                                }
                                "number_literal" => {
                                    // Array size
                                    let size_str = &source[declarator_child.start_byte()
                                        ..declarator_child.end_byte()];
                                    array_size = size_str.parse().ok();
                                }
                                _ => {}
                            }
                        }
                    }

                    // If we found both name and size, create BufferInfo
                    if let (Some(name), Some(size)) = (member_name, array_size) {
                        return Some(BufferInfo {
                            name,
                            size: BufferSize::Static(size),
                            element_type: "struct_member".to_string(),
                            allocation_line: node.start_position().row + 1,
                            alloc_bytes: None,
                        });
                    }
                }
            }
        }
        None
    }

    /// Extract VLA (Variable Length Array) from declaration node
    fn extract_vla_from_declaration(
        &self,
        node: &Node,
        source: &str,
        _typedefs: &HashMap<String, usize>,
    ) -> Option<BufferInfo> {
        // Look for array_declarator with identifier size (not number_literal)
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "init_declarator" {
                    // Check first child for array_declarator
                    if let Some(declarator) = child.child(0) {
                        if declarator.kind() == "array_declarator" {
                            return self.extract_vla_from_array_declarator(&declarator, source);
                        }
                    }
                } else if child.kind() == "array_declarator" {
                    return self.extract_vla_from_array_declarator(&child, source);
                }
            }
        }
        None
    }

    /// Extract VLA from array_declarator if size is symbolic
    fn extract_vla_from_array_declarator(&self, node: &Node, source: &str) -> Option<BufferInfo> {
        let mut var_name: Option<String> = None;
        let mut size_expr: Option<String> = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" if i == 0 => {
                        var_name = Some(source[child.start_byte()..child.end_byte()].to_string());
                    }
                    "identifier" if i > 0 => {
                        // This is a symbolic size (VLA)
                        let expr = &source[child.start_byte()..child.end_byte()];
                        // Verify it's not a number
                        if !expr.chars().all(|c| c.is_numeric()) {
                            size_expr = Some(expr.to_string());
                        }
                    }
                    "number_literal" => {
                        // This is a static size, not a VLA
                        return None;
                    }
                    _ => {}
                }
            }
        }

        if let (Some(name), Some(expr)) = (var_name, size_expr) {
            Some(BufferInfo {
                name,
                size: BufferSize::Symbolic(expr),
                element_type: "unknown".to_string(),
                allocation_line: node.start_position().row + 1,
                alloc_bytes: None,
            })
        } else {
            None
        }
    }

    /// Analyze pointer aliases in the source code using AST traversal
    fn analyze_pointer_aliases(
        &self,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
    ) -> HashMap<String, PointerAlias> {
        let mut aliases = HashMap::new();

        // Parse the source code into AST
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&crate::parser::c_language())
            .expect("Error loading C grammar");

        let tree = match parser.parse(source, None) {
            Some(t) => t,
            None => return aliases,
        };

        let root_node = tree.root_node();

        // Traverse AST to find all pointer alias declarations
        self.extract_aliases_from_ast(&root_node, source, buffers, &mut aliases);

        aliases
    }

    /// Recursively extract pointer aliases from AST
    fn extract_aliases_from_ast(
        &self,
        node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
        aliases: &mut HashMap<String, PointerAlias>,
    ) {
        // Check if this node is a declaration
        if node.kind() == "declaration" {
            if let Some(alias) = self.extract_alias_from_declaration(node, source, buffers) {
                aliases.insert(alias.alias_name.clone(), alias);
            }
        }

        // Check for assignment expressions: "data = dataBadBuffer;"
        if node.kind() == "expression_statement" {
            if let Some(assign) = node.child(0) {
                if assign.kind() == "assignment_expression" {
                    if let (Some(left), Some(right)) = (
                        assign.child_by_field_name("left"),
                        assign.child_by_field_name("right"),
                    ) {
                        if left.kind() == "identifier" && right.kind() == "identifier" {
                            let lhs = &source[left.start_byte()..left.end_byte()];
                            let rhs = &source[right.start_byte()..right.end_byte()];
                            if buffers.contains_key(rhs) {
                                aliases.insert(
                                    lhs.to_string(),
                                    PointerAlias {
                                        alias_name: lhs.to_string(),
                                        original_buffer: rhs.to_string(),
                                        element_size_bytes: None,
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }

        // Recursively process children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.extract_aliases_from_ast(&child, source, buffers, aliases);
            }
        }
    }

    /// Analyze typedef declarations for array types
    fn analyze_typedefs(&self, source: &str) -> HashMap<String, usize> {
        let mut typedefs = HashMap::new();

        // Pattern: typedef type TypeName[SIZE];
        let typedef_pattern = r"typedef\s+(?:\w+\s+)*\w+\s+(\w+)\s*\[\s*(\d+)\s*\]";

        if let Ok(re) = regex::Regex::new(typedef_pattern) {
            for caps in re.captures_iter(source) {
                if let (Some(typedef_name), Some(size_str)) = (caps.get(1), caps.get(2)) {
                    if let Ok(size) = size_str.as_str().parse::<usize>() {
                        typedefs.insert(typedef_name.as_str().to_string(), size);
                    }
                }
            }
        }

        typedefs
    }

    /// Analyze struct/union members that use typedef array types
    /// This handles cases like: struct { IntArray numbers; }
    fn analyze_struct_typedef_members(
        &self,
        source: &str,
        typedefs: &HashMap<String, usize>,
        buffers: &mut HashMap<String, BufferInfo>,
    ) {
        let lines: Vec<&str> = source.lines().collect();

        let re = regex::Regex::new(r"^\s*(\w+)\s+(\w+)\s*;").ok();
        for (line_idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Pattern: TypedefName member_name;
            // Look for lines that match typedef usage inside structs/unions
            if let Some(re) = &re {
                if let Some(caps) = re.captures(trimmed) {
                    if let (Some(type_match), Some(member_match)) = (caps.get(1), caps.get(2)) {
                        let type_name = type_match.as_str();
                        let member_name = member_match.as_str();

                        // Check if this is a known typedef
                        if let Some(&size) = typedefs.get(type_name) {
                            // Add as a tracked buffer using the member name
                            buffers.insert(
                                member_name.to_string(),
                                BufferInfo {
                                    name: member_name.to_string(),
                                    size: BufferSize::Static(size),
                                    element_type: type_name.to_string(),
                                    allocation_line: line_idx + 1,
                                    alloc_bytes: None,
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    /// Evaluate a memcpy/memmove count expression as a byte count.
    /// Handles:
    ///   - N*sizeof(T) → N * type_size_bytes
    ///   - (strlen(VAR)+1)*sizeof(char) → source_array_size * 1 (CWE-193)
    ///   - (wcslen(VAR)+1)*sizeof(wchar_t) → source_array_size * 4 (CWE-193)
    ///   - Plain number → that many bytes
    fn evaluate_count_bytes(
        &self,
        count_expr: &str,
        buffers: &HashMap<String, BufferInfo>,
    ) -> Option<usize> {
        let trimmed = count_expr.trim();

        // Plain number
        if let Ok(n) = trimmed.parse::<usize>() {
            return Some(n);
        }

        // N*sizeof(T) → N * sizeof_bytes
        if trimmed.contains('*') && trimmed.contains("sizeof") {
            // Try strlen/wcslen resolution first
            if let Some(bytes) = self.resolve_strlen_sizeof_bytes(trimmed, buffers) {
                return Some(bytes);
            }
            // Fall back to plain N*sizeof(T)
            if let Some(mult_pos) = trimmed.find('*') {
                let count_str = trimmed[..mult_pos].trim();
                let sizeof_str = trimmed[mult_pos + 1..].trim();

                let count = buffer_size::extract_numeric_value(count_str);
                let sizeof_val = buffer_size::extract_sizeof_value(sizeof_str);

                if let (Some(c), Some(s)) = (count, sizeof_val) {
                    return Some(c * s);
                }
            }
        }

        // strlen(VAR) + 1 (without sizeof, implies sizeof(char)=1)
        if let Some(bytes) = self.resolve_strlen_plus_one(trimmed, buffers) {
            return Some(bytes);
        }

        None
    }

    /// Resolve (strlen(VAR)+1)*sizeof(char) or (wcslen(VAR)+1)*sizeof(wchar_t)
    /// to byte count using the source array size.
    fn resolve_strlen_sizeof_bytes(
        &self,
        expr: &str,
        buffers: &HashMap<String, BufferInfo>,
    ) -> Option<usize> {
        // Detect strlen or wcslen function call
        let (fn_name, elem_size) = if expr.contains("strlen") {
            ("strlen", 1usize)
        } else if expr.contains("wcslen") {
            ("wcslen", 4usize) // sizeof(wchar_t) = 4
        } else {
            return None;
        };

        // Extract variable name from strlen(VAR) or wcslen(VAR)
        let fn_start = expr.find(fn_name)?;
        let paren_start = expr[fn_start..].find('(')? + fn_start + 1;
        let paren_end = expr[paren_start..].find(')')? + paren_start;
        let var_name = expr[paren_start..paren_end].trim();

        // Look up variable in buffers
        let var_info = buffers.get(var_name)?;
        let var_elements = match var_info.size {
            BufferSize::Static(s) | BufferSize::DynamicCalculated(s) => s,
            _ => return None,
        };

        // Check for +1 pattern (null terminator inclusion)
        let has_plus_one = expr.contains("+ 1") || expr.contains("+1");

        // strlen(VAR) returns at most var_elements - 1
        // strlen(VAR) + 1 returns at most var_elements
        let count_elements = if has_plus_one {
            var_elements
        } else {
            var_elements.saturating_sub(1)
        };

        // Apply sizeof multiplier from the expression
        let sizeof_val = if expr.contains("sizeof") {
            buffer_size::extract_sizeof_value(expr).unwrap_or(elem_size)
        } else {
            elem_size
        };

        Some(count_elements * sizeof_val)
    }

    /// Resolve strlen(VAR)+1 or wcslen(VAR)+1 (without sizeof wrapper)
    /// Used for strncpy(dest, src, strlen(src)+1) patterns
    fn resolve_strlen_plus_one(
        &self,
        expr: &str,
        buffers: &HashMap<String, BufferInfo>,
    ) -> Option<usize> {
        let fn_name = if expr.contains("strlen") {
            "strlen"
        } else if expr.contains("wcslen") {
            "wcslen"
        } else {
            return None;
        };

        // Extract variable name
        let fn_start = expr.find(fn_name)?;
        let paren_start = expr[fn_start..].find('(')? + fn_start + 1;
        let paren_end = expr[paren_start..].find(')')? + paren_start;
        let var_name = expr[paren_start..paren_end].trim();

        // Look up variable in buffers
        let var_info = buffers.get(var_name)?;
        let var_elements = match var_info.size {
            BufferSize::Static(s) | BufferSize::DynamicCalculated(s) => s,
            _ => return None,
        };

        // Check for +1
        let has_plus_one = expr.contains("+ 1") || expr.contains("+1");

        if has_plus_one {
            Some(var_elements)
        } else {
            Some(var_elements.saturating_sub(1))
        }
    }

    /// Get array name from subscript expression node
    fn get_array_name_from_subscript(&self, node: &Node, source: &str) -> Option<String> {
        let array_node = node.child(0)?;

        // If the child is itself a subscript_expression, we need the full text
        // For nested subscripts like matrix[0][5], this will return "matrix[0]"
        if array_node.kind() == "subscript_expression" {
            let text = &source[array_node.start_byte()..array_node.end_byte()];
            return Some(text.to_string());
        }

        let text = &source[array_node.start_byte()..array_node.end_byte()];

        // Check if this is member access (contains '.' or '->')
        if text.contains('.') {
            // Extract the member name after the last '.'
            if let Some(member) = text.split('.').next_back() {
                return Some(member.to_string());
            }
        }

        if text.contains("->") {
            // Extract the member name after the last '->'
            if let Some(member) = text.rsplit("->").next() {
                return Some(member.to_string());
            }
        }

        // Handle regular cases like arr[i], ptr[j]
        // Extract the base identifier
        let identifier = text
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .find(|s| !s.is_empty())?;

        Some(identifier.to_string())
    }

    /// Get the subscript index value (constant or variable)
    fn get_subscript_index_value(
        &self,
        node: &Node,
        source: &str,
        macro_constants: &HashMap<String, i64>,
    ) -> Option<IndexValue> {
        let index_node = self.get_subscript_index(node)?;
        let index_text = &source[index_node.start_byte()..index_node.end_byte()];

        // Try to parse as simple constant (now supports negative indices)
        if let Ok(const_val) = index_text.trim().parse::<isize>() {
            return Some(IndexValue::Constant(const_val));
        }

        // A bare name that's a known compile-time constant -- most commonly
        // a C `enum` constant (e.g. `MOUSE_BUTTON_LEFT = 0`) used to index a
        // fixed-size lookup table (`buttonState[MOUSE_BUTTON_LEFT]`). Unlike
        // a `#define`, tree-sitter never substitutes an enumerator's value
        // inline, so without this lookup every such index looks like an
        // unbounded runtime variable even though its value is fixed at
        // compile time (task 443). `collect_macro_constants` already folds
        // enum constants into this same map (see `Arr30C::collect_constants`
        // doc comment) -- restricted to a bare identifier (no `.`/`->`/
        // arithmetic) so this can't misfire on a struct field or expression
        // that merely shares a macro's name as a substring.
        if index_node.kind() == "identifier" {
            if let Some(&value) = macro_constants.get(index_text.trim()) {
                return Some(IndexValue::Constant(value as isize));
            }
        }

        // Try to evaluate as expression
        if let Some(eval_val) = self.evaluate_index_expression(index_text, source) {
            return Some(IndexValue::Expression(
                index_text.to_string(),
                Some(eval_val),
            ));
        }

        // Check if it's an arithmetic expression with variable
        if self.is_arithmetic_expression(index_text) {
            return Some(IndexValue::Expression(index_text.to_string(), None));
        }

        // Try to resolve variable to a constant value via simple constant propagation
        if let Some(const_val) = self.try_resolve_variable_to_constant(index_text, node, source) {
            return Some(IndexValue::Constant(const_val));
        }

        // It's a simple variable
        Some(IndexValue::Variable(index_text.to_string()))
    }

    /// Evaluate compile-time constant index expressions
    fn evaluate_index_expression(&self, expr: &str, source: &str) -> Option<isize> {
        let expr = expr.trim();

        // Pattern 1: sizeof(var) - N
        if expr.contains("sizeof") && expr.contains('-') {
            return self.evaluate_sizeof_expression(expr, source);
        }

        // Pattern 2: Simple arithmetic with constants (e.g., "10 - 1")
        if let Some(result) = buffer_size::evaluate_simple_arithmetic(expr) {
            return Some(result);
        }

        None
    }

    /// Evaluate sizeof expressions like "sizeof(buffer) - 1"
    fn evaluate_sizeof_expression(&self, expr: &str, source: &str) -> Option<isize> {
        // Extract sizeof target and arithmetic operation
        let re = regex::Regex::new(r"sizeof\s*\(\s*(\w+)\s*\)\s*(-|\+)\s*(\d+)").ok()?;
        let caps = re.captures(expr)?;

        let var_name = caps.get(1)?.as_str();
        let op = caps.get(2)?.as_str();
        let operand: usize = caps.get(3)?.as_str().parse().ok()?;

        // Find the buffer size by searching for declaration in source
        if let Some(size) = self.find_array_size_in_source(var_name, source) {
            match op {
                "-" if operand <= size => {
                    return Some((size - operand) as isize);
                }
                "+" => return Some((size + operand) as isize),
                _ => {}
            }
        }

        None
    }

    /// Find array size from source code for a given variable name
    fn find_array_size_in_source(&self, var_name: &str, source: &str) -> Option<usize> {
        // Look for declarations like: type var_name[SIZE];
        let pattern = format!(r"\b{}\s*\[\s*(\d+)\s*\]", regex::escape(var_name));
        let re = regex::Regex::new(&pattern).ok()?;

        if let Some(caps) = re.captures(source) {
            return caps.get(1)?.as_str().parse().ok();
        }

        None
    }

    /// Check if expression contains arithmetic operators
    fn is_arithmetic_expression(&self, expr: &str) -> bool {
        expr.contains('+') || expr.contains('-') || expr.contains('*') || expr.contains('/')
    }

    /// Attempt to resolve a variable to a constant through simple intraprocedural constant propagation
    fn try_resolve_variable_to_constant(
        &self,
        var_name: &str,
        current_node: &Node,
        source: &str,
    ) -> Option<isize> {
        // Check if this variable is a loop counter - if so, don't resolve to constant
        // Loop counters change value during execution
        if let Some(for_node) = find_containing_for_loop(current_node) {
            if let Some(loop_var) = self.extract_loop_index_variable(&for_node, source) {
                if loop_var == var_name {
                    // This is a loop counter - don't resolve to its initial value
                    return None;
                }
            }
        }

        // Find enclosing function
        let func_node = find_containing_function(current_node)?;

        // Search for assignments to var_name within this function
        // Look for pattern: var_name = constant_literal
        let func_text = &source[func_node.start_byte()..func_node.end_byte()];

        // Regex pattern: var_name = digit+ OR var_name = -digit+
        let pattern = format!(r"\b{}\s*=\s*(-?\d+)", regex::escape(var_name));
        let re = regex::Regex::new(&pattern).ok()?;

        // Check for non-constant assignments (e.g., var = func_call(...), var = other_var)
        // Pattern: var_name = <something> but exclude comparison operators (==, !=, <=, >=)
        let any_assign_pattern = format!(r"\b{}\s*=[^=!<>]", regex::escape(var_name));
        let any_assign_re = regex::Regex::new(&any_assign_pattern).ok()?;
        let total_assign_count = any_assign_re.find_iter(func_text).count();

        if total_assign_count > 1 {
            // Multiple assignments — check if ALL are constant.
            // If so, resolve to the last value (handles "data = -1; data = 7;" patterns
            // where an initialization is overwritten by a known-good value).
            let const_count = re.find_iter(func_text).count();
            if const_count == total_assign_count {
                if let Some(caps) = re.captures_iter(func_text).last() {
                    if let Some(value_str) = caps.get(1) {
                        return value_str.as_str().parse::<isize>().ok();
                    }
                }
            }
            return None;
        }

        // Only one assignment - resolve it
        if let Some(caps) = re.captures(func_text) {
            if let Some(value_str) = caps.get(1) {
                return value_str.as_str().parse::<isize>().ok();
            }
        }

        None
    }

    /// Resolve what `name` evaluates to at `position_node`'s source
    /// position, scope-correctly: finds the *specific* declaration bound to
    /// `name` at that point (disambiguating shadowed re-declarations in
    /// sibling/nested blocks — see `find_enclosing_declaration_for_identifier`),
    /// then scans only that declaration's enclosing block, in source order,
    /// for the last value assigned to `name` before `position_node`. If that
    /// value is itself read through a pointer dereference (`*ptr`), resolves
    /// through the pointer's current pointee instead of giving up (depth-
    /// bounded to avoid pathological chains — this bucket only ever needs
    /// one hop: read-through-alias followed by a plain constant).
    fn resolve_value_of_identifier_at(
        &self,
        name: &str,
        position_node: &Node,
        source: &str,
        depth: u8,
    ) -> Option<isize> {
        const MAX_DEPTH: u8 = 3;
        if depth > MAX_DEPTH {
            return None;
        }
        let value_node = self.find_last_assigned_value_expr(name, position_node, source)?;
        self.resolve_value_expr(&value_node, source, depth)
    }

    /// Find the value expression most recently assigned to `name` before
    /// `position_node`, scope-correctly (disambiguating shadowed
    /// re-declarations in sibling/nested blocks via
    /// `find_enclosing_declaration_for_identifier`), without resolving it
    /// further. Shared by `resolve_value_of_identifier_at` (which resolves
    /// the result to a constant) and `is_bounded_by_read_call_length`
    /// (which instead checks whether it's a `recv()`/`read()`-family call).
    fn find_last_assigned_value_expr<'a>(
        &self,
        name: &str,
        position_node: &Node<'a>,
        source: &str,
    ) -> Option<Node<'a>> {
        let decl = find_enclosing_declaration_for_identifier(position_node, name, source)?;
        let block = decl.parent()?;
        // A `for (T name = init; ...) { ... }` declaration's parent is the
        // `for_statement` itself, not a `compound_statement` of sequential
        // statements -- the "scan this block in source order for the last
        // assignment" model below doesn't apply: the update expression
        // (`name++`) sits textually *before* the body in the AST despite
        // running *after* it each iteration, and the loop variable ranges
        // over values rather than holding one constant. Resolving it to its
        // bare initializer (the only thing this scan would find, since
        // `i++` doesn't match `plain_assignment_value`'s plain-assignment
        // shape) would wrongly report every use of the loop variable as its
        // initial value -- e.g. `buffer[i]` inside the loop body would look
        // like `buffer[0]` always, hiding a real off-by-one overrun. Bail
        // out so the caller falls back to its loop/VRA-aware bounds check
        // instead.
        if block.kind() != "compound_statement" {
            return None;
        }

        let mut last_value_expr: Option<Node> = None;
        if let Some(init) = Self::declaration_initializer_for(&decl, name, source) {
            last_value_expr = Some(init);
        }
        for i in 0..block.child_count() {
            let Some(stmt) = block.child(i) else { continue };
            if stmt.id() == decl.id() {
                continue;
            }
            if stmt.start_byte() <= decl.start_byte()
                || stmt.start_byte() >= position_node.start_byte()
            {
                continue;
            }
            if let Some(value) = Self::plain_assignment_value(&stmt, name, source) {
                last_value_expr = Some(value);
            }
        }

        last_value_expr
    }

    /// Resolve a value EXPRESSION node to a constant: a numeric literal
    /// directly, a plain identifier (recurses, scope-correctly, on that
    /// name at the expression's own position), or a pointer dereference
    /// (`*ptr` — resolves through whatever the pointer currently aliases,
    /// via `resolve_value_written_through_alias`).
    fn resolve_value_expr(&self, value_node: &Node, source: &str, depth: u8) -> Option<isize> {
        match value_node.kind() {
            "number_literal" => {
                let text = &source[value_node.start_byte()..value_node.end_byte()];
                text.trim().parse::<isize>().ok()
            }
            "unary_expression" => {
                // Handles a leading-minus literal, e.g. `-1`.
                let text = &source[value_node.start_byte()..value_node.end_byte()];
                text.trim().parse::<isize>().ok()
            }
            "identifier" => {
                let name = &source[value_node.start_byte()..value_node.end_byte()];
                self.resolve_value_of_identifier_at(name, value_node, source, depth + 1)
            }
            "pointer_expression" => {
                let op = value_node.child_by_field_name("operator")?;
                if &source[op.start_byte()..op.end_byte()] != "*" {
                    return None; // address-of, not a dereference read
                }
                let ptr_arg = value_node.child_by_field_name("argument")?;
                if ptr_arg.kind() != "identifier" {
                    return None;
                }
                let ptr_name = &source[ptr_arg.start_byte()..ptr_arg.end_byte()];
                let func_node = find_containing_function(value_node)?;
                let pointee_map = Self::build_pointee_map(&func_node, source);
                let pointee = pointee_map.get(ptr_name)?;
                self.resolve_value_written_through_alias(pointee, value_node, source, depth + 1)
            }
            _ => None,
        }
    }

    /// Find the most recent (highest byte offset, but still before
    /// `position_node`) statement of the form `*ptr = <expr>;` anywhere in
    /// the enclosing function where `ptr` is known (via the pointee map) to
    /// alias `pointee_name`, and resolve `<expr>` at that write's own
    /// position. This is what threads a write through one alias
    /// (`*dataPtr1 = data;`) to a read through a different alias of the same
    /// storage (`*dataPtr2`).
    fn resolve_value_written_through_alias(
        &self,
        pointee_name: &str,
        position_node: &Node,
        source: &str,
        depth: u8,
    ) -> Option<isize> {
        let func_node = find_containing_function(position_node)?;
        let pointee_map = Self::build_pointee_map(&func_node, source);

        let mut best: Option<Node> = None;
        Self::for_each_descendant(&func_node, &mut |n| {
            if n.kind() != "assignment_expression" || n.start_byte() >= position_node.start_byte() {
                return;
            }
            let Some(left) = n.child_by_field_name("left") else {
                return;
            };
            if left.kind() != "pointer_expression" {
                return;
            }
            let Some(ptr_arg) = left.child_by_field_name("argument") else {
                return;
            };
            if ptr_arg.kind() != "identifier" {
                return;
            }
            let ptr_name = &source[ptr_arg.start_byte()..ptr_arg.end_byte()];
            if pointee_map.get(ptr_name).map(String::as_str) != Some(pointee_name) {
                return;
            }
            if best.is_none_or(|b: Node| n.start_byte() > b.start_byte()) {
                best = Some(n);
            }
        });

        let write = best?;
        let value_node = write.child_by_field_name("right")?;
        self.resolve_value_expr(&value_node, source, depth)
    }

    /// The initializer value node of an `init_declarator` binding `name`
    /// within `decl` (a `declaration` node), if any.
    fn declaration_initializer_for<'a>(
        decl: &Node<'a>,
        name: &str,
        source: &str,
    ) -> Option<Node<'a>> {
        for i in 0..decl.child_count() {
            let child = decl.child(i)?;
            if child.kind() != "init_declarator" {
                continue;
            }
            let declarator = child.child_by_field_name("declarator")?;
            if get_identifier_from_declarator(&declarator, source) != name {
                continue;
            }
            return child.child_by_field_name("value");
        }
        None
    }

    /// The RHS value node of a plain `name = <expr>;` assignment statement
    /// (an `expression_statement` wrapping an `assignment_expression` whose
    /// LHS is exactly the bare identifier `name`), if `stmt` is one.
    fn plain_assignment_value<'a>(stmt: &Node<'a>, name: &str, source: &str) -> Option<Node<'a>> {
        if stmt.kind() != "expression_statement" {
            return None;
        }
        let assign = stmt.child(0)?;
        if assign.kind() != "assignment_expression" {
            return None;
        }
        let left = assign.child_by_field_name("left")?;
        if left.kind() != "identifier" || &source[left.start_byte()..left.end_byte()] != name {
            return None;
        }
        assign.child_by_field_name("right")
    }

    /// Map each pointer variable declared/assigned `&var` to the name of the
    /// storage it aliases (e.g. `"dataPtr1" -> "data"`), by one linear scan
    /// of `func_node`. Deliberately narrow: address-of only, no pointer
    /// arithmetic, no reassignment tracking — this bucket only needs `int
    /// *p = &x;`-shaped aliasing, and the outer variable is never re-pointed
    /// once declared in the Juliet dataflow-32 family this targets.
    fn build_pointee_map(func_node: &Node, source: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        Self::for_each_descendant(func_node, &mut |n| {
            let (declarator, value) = match n.kind() {
                "init_declarator" => {
                    let Some(d) = n.child_by_field_name("declarator") else {
                        return;
                    };
                    let Some(v) = n.child_by_field_name("value") else {
                        return;
                    };
                    (d, v)
                }
                "assignment_expression" => {
                    let Some(l) = n.child_by_field_name("left") else {
                        return;
                    };
                    let Some(r) = n.child_by_field_name("right") else {
                        return;
                    };
                    if l.kind() != "identifier" {
                        return;
                    }
                    (l, r)
                }
                _ => return,
            };
            if value.kind() != "pointer_expression" {
                return;
            }
            let Some(op) = value.child_by_field_name("operator") else {
                return;
            };
            if &source[op.start_byte()..op.end_byte()] != "&" {
                return; // dereference, not address-of
            }
            let Some(addressed) = value.child_by_field_name("argument") else {
                return;
            };
            if addressed.kind() != "identifier" {
                return;
            }
            let Some(ptr_name) = find_identifier_in_declarator(&declarator, source) else {
                return;
            };
            let pointee_name = source[addressed.start_byte()..addressed.end_byte()].to_string();
            map.insert(ptr_name, pointee_name);
        });
        map
    }

    /// Visit every descendant of `node` (not including `node` itself),
    /// preorder, calling `visit` on each.
    fn for_each_descendant<'a>(node: &Node<'a>, visit: &mut impl FnMut(Node<'a>)) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                visit(child);
                Self::for_each_descendant(&child, visit);
            }
        }
    }

    // Removed: find_enclosing_function - now using ast_utils::find_containing_function

    // Removed: is_function_parameter - now using ast_utils::is_function_parameter with find_containing_function

    /// Returns true if `function_node` is declared `static` or uses a STATIC macro prefix.
    fn is_static_function(function_node: &Node, source: &str) -> bool {
        for i in 0..function_node.child_count() {
            if let Some(child) = function_node.child(i) {
                if child.kind() == "storage_class_specifier" {
                    if &source[child.start_byte()..child.end_byte()] == "static" {
                        return true;
                    }
                }
            }
        }
        let func_text = &source[function_node.start_byte()..function_node.end_byte()];
        let before_paren = func_text.split('(').next().unwrap_or("");
        before_paren
            .split_whitespace()
            .any(|tok| tok.contains("STATIC"))
    }

    /// Returns true if the named parameter of `func_node` is declared with a
    /// non-primitive (user-defined) type such as an enum typedef.
    /// Used to suppress ARR30-C for static functions whose index parameters are
    /// enum values — those are controlled by definition (e.g., `led_id_t`).
    fn param_has_user_defined_type(func_node: &Node, param_name: &str, source: &str) -> bool {
        let primitive_types = [
            "int",
            "long",
            "short",
            "char",
            "float",
            "double",
            "void",
            "signed",
            "unsigned",
            "size_t",
            "ssize_t",
            "ptrdiff_t",
            "intptr_t",
            "uintptr_t",
            "bool",
            "_Bool",
            "int8_t",
            "int16_t",
            "int32_t",
            "int64_t",
            "uint8_t",
            "uint16_t",
            "uint32_t",
            "uint64_t",
        ];
        if let Some(declarator) = func_node.child_by_field_name("declarator") {
            if let Some(param_list) = find_param_list_node(&declarator) {
                for i in 0..param_list.child_count() {
                    if let Some(param) = param_list.child(i) {
                        if param.kind() != "parameter_declaration" {
                            continue;
                        }
                        // Check if the declarator contains param_name
                        let param_text = &source[param.start_byte()..param.end_byte()];
                        if !param_text.contains(param_name) {
                            continue;
                        }
                        // Get the type
                        if let Some(type_node) = param.child_by_field_name("type") {
                            let type_text = &source[type_node.start_byte()..type_node.end_byte()];
                            let stripped = type_text
                                .replace("const", "")
                                .replace("volatile", "")
                                .replace("restrict", "")
                                .replace("struct", "")
                                .replace("union", "")
                                .replace("enum", "");
                            let stripped = stripped.trim();
                            return !primitive_types.contains(&stripped);
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if function has ANY bounds validation for a parameter
    fn has_function_parameter_bounds_check(
        &self,
        func_node: &Node,
        param_name: &str,
        source: &str,
    ) -> bool {
        let func_text = &source[func_node.start_byte()..func_node.end_byte()];

        // Check for various bounds checking patterns:
        // 1. if (param < size) or if (param >= size) return
        // 2. Loop with param in condition: for (i = 0; i < size; i++)
        // 3. Presence of size/length/count parameter

        // IMPORTANT: Check for OFF-BY-ONE errors first!
        // Pattern: if (size < param) is WRONG - should be if (size <= param)
        // This is an off-by-one error common in realloc/resize code
        let off_by_one_pattern =
            format!(r"\bif\s*\(\s*\w+\s*<\s*{}\s*\)", regex::escape(param_name));
        if let Ok(re) = regex::Regex::new(&off_by_one_pattern) {
            if re.is_match(func_text) {
                // Found "if (size < param)" pattern - this is INSUFFICIENT bounds checking
                // It should be "if (size <= param)" to properly handle the case where size == param
                return false;
            }
        }

        let bounds_patterns = [
            format!(r"{}\s*<\s*\w+", regex::escape(param_name)), // param < size
            format!(r"\w+\s*>\s*{}", regex::escape(param_name)), // size > param
            format!(r"{}\s*>=\s*\w+", regex::escape(param_name)), // param >= size (with return/check)
            format!(r"\w+\s*<=\s*{}", regex::escape(param_name)), // size <= param (correct for realloc)
            format!(r"if\s*\([^)]*{}", regex::escape(param_name)), // if statement with param
        ];

        for pattern in &bounds_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(func_text) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if array access is within a recursive function
    fn is_recursive_array_access(&self, subscript_node: &Node, source: &str) -> bool {
        // Find enclosing function
        if let Some(func_node) = find_containing_function(subscript_node) {
            // Get function name
            for i in 0..func_node.child_count() {
                if let Some(child) = func_node.child(i) {
                    if child.kind() == "function_declarator" {
                        // Get function name (first child of function_declarator)
                        if let Some(name_node) = child.child(0) {
                            let func_name = &source[name_node.start_byte()..name_node.end_byte()];

                            // Search function body for calls to itself
                            let func_text = &source[func_node.start_byte()..func_node.end_byte()];

                            // Look for function calls in the body (skip the declaration part)
                            // Pattern: function_name(
                            let call_pattern = format!(r"{}\s*\(", regex::escape(func_name));
                            if let Ok(re) = regex::Regex::new(&call_pattern) {
                                // Count matches - if more than 1, it's recursive (declaration + call)
                                let matches: Vec<_> = re.find_iter(func_text).collect();
                                return matches.len() > 1;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if a recursive function has dangerous index modification patterns
    /// Returns true if recursion modifies indices in a way that will exceed bounds
    fn has_recursive_index_modification(
        &self,
        subscript_node: &Node,
        index_text: &str,
        source: &str,
        array_size: usize,
    ) -> bool {
        if !self.is_recursive_array_access(subscript_node, source) {
            return false;
        }

        if let Some(func_node) = find_containing_function(subscript_node) {
            let func_text = &source[func_node.start_byte()..func_node.end_byte()];

            // Get function name for recursive call pattern
            let func_name = match self.get_function_name(&func_node, source) {
                Some(name) => name,
                None => return false,
            };

            // Look for recursive calls with index modifications like: func(arr, index + 2, ...)
            // Pattern: function_name(.*index \+ \d+
            let modification_pattern = format!(
                r"{}\s*\([^)]*{}\s*\+\s*(\d+)",
                regex::escape(&func_name),
                regex::escape(index_text)
            );
            if let Ok(re) = regex::Regex::new(&modification_pattern) {
                if let Some(caps) = re.captures(func_text) {
                    if let Some(increment) = caps.get(1) {
                        if let Ok(inc_val) = increment.as_str().parse::<usize>() {
                            // Check if there's a depth limit
                            // Look for patterns like: if (depth > N) return
                            let depth_pattern = r"if\s*\(\s*\w+\s*>\s*(\d+)\s*\)";
                            if let Ok(depth_re) = regex::Regex::new(depth_pattern) {
                                if let Some(depth_caps) = depth_re.captures(func_text) {
                                    if let Some(max_depth) = depth_caps.get(1) {
                                        if let Ok(max_d) = max_depth.as_str().parse::<usize>() {
                                            // Calculate maximum index: inc_val * max_d
                                            // If this exceeds array_size, it's a violation
                                            return inc_val * max_d >= array_size;
                                        }
                                    }
                                }
                            }
                            // No depth limit found, or couldn't parse - flag as dangerous
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Get function name from function_definition node
    fn get_function_name(&self, func_node: &Node, source: &str) -> Option<String> {
        for i in 0..func_node.child_count() {
            if let Some(child) = func_node.child(i) {
                if child.kind() == "function_declarator" {
                    if let Some(name_node) = child.child(0) {
                        return Some(
                            source[name_node.start_byte()..name_node.end_byte()].to_string(),
                        );
                    }
                }
            }
        }
        None
    }

    /// Enhanced bounds check that considers actual buffer size
    fn has_proper_bounds_check(
        &self,
        node: &Node,
        source: &str,
        buffer_size: usize,
        macro_constants: &HashMap<String, i64>,
    ) -> bool {
        // Check loop-based bounds checking
        if let Some(for_node) = find_containing_for_loop(node) {
            if self.check_for_loop_bounds_against_size(
                &for_node,
                source,
                buffer_size,
                macro_constants,
            ) {
                return true;
            }
        }

        // Check conditional bounds checking
        if let Some(if_node) = find_containing_if_statement(node) {
            if self.check_if_bounds_against_size(&if_node, source, buffer_size, macro_constants) {
                return true;
            }
        }

        false
    }

    /// Check if there's any form of dynamic bounds checking
    fn has_dynamic_bounds_check(&self, node: &Node, source: &str) -> bool {
        // Check for loop-based bounds checking
        if let Some(for_node) = find_containing_for_loop(node) {
            // Use empty string for index to do generic check
            if self.check_for_loop_bounds_generic(&for_node, source) {
                return true;
            }
        }

        // Check for conditional bounds checking
        if let Some(if_node) = find_containing_if_statement(node) {
            if self.check_if_bounds_generic(&if_node, source) {
                return true;
            }
        }

        // Check for function-level bounds checking (parameter validation).
        // Matched against each identifier's own text, not the whole function's
        // raw span, so a comment or string literal mentioning "size"/"length"/
        // "count" can't fake a bounds check that isn't actually there.
        if let Some(func_node) = find_containing_function(node) {
            let has_bound_named_identifier =
                query::find_descendants_of_kind(func_node, "identifier")
                    .iter()
                    .any(|id| {
                        let text = &source[id.start_byte()..id.end_byte()];
                        text.contains("size") || text.contains("length") || text.contains("count")
                    });
            if has_bound_named_identifier {
                return true;
            }
        }

        false
    }

    // Removed: find_containing_for_loop - now using ast_utils::find_containing_for_loop
    // Removed: find_containing_if_statement - now using ast_utils::find_containing_if_statement

    /// Check for loop bounds against specific buffer size
    fn check_for_loop_bounds_against_size(
        &self,
        for_node: &Node,
        source: &str,
        size: usize,
        macro_constants: &HashMap<String, i64>,
    ) -> bool {
        // Look for a condition comparison like `i < 10` where the bound is
        // exactly `size` — scoped to the loop's own condition (not its body),
        // and matched against the comparison operator/operand nodes, not a
        // whole-loop text scan a comment or unrelated body statement could
        // fake a match in.
        if let Some(condition) = for_node.child_by_field_name("condition") {
            let has_exact_size_bound =
                query::find_descendants_of_kind(condition, "binary_expression")
                    .iter()
                    .any(|cmp| {
                        cmp.child_by_field_name("operator")
                            .is_some_and(|o| &source[o.start_byte()..o.end_byte()] == "<")
                            && cmp.child_by_field_name("right").is_some_and(|r| {
                                r.kind() == "number_literal"
                                    && source[r.start_byte()..r.end_byte()]
                                        .parse::<usize>()
                                        .is_ok_and(|n| n == size)
                            })
                    });
            if has_exact_size_bound {
                return true;
            }
        }

        // Extract the loop index variable name
        let index_var = self.extract_loop_index_variable(for_node, source);
        let index_text = index_var.as_deref().unwrap_or("");

        // Check loop condition for safe bounds
        for i in 0..for_node.child_count() {
            if let Some(child) = for_node.child(i) {
                if let Some(result) = self.condition_child_bounds_verdict(
                    &child,
                    source,
                    size,
                    macro_constants,
                    index_text,
                ) {
                    return result;
                }
            }
        }

        // Also check inside parenthesized expressions
        for i in 0..for_node.child_count() {
            if let Some(child) = for_node.child(i) {
                if child.kind() == "parenthesized_expression" {
                    for j in 0..child.child_count() {
                        if let Some(grandchild) = child.child(j) {
                            if let Some(result) = self.condition_child_bounds_verdict(
                                &grandchild,
                                source,
                                size,
                                macro_constants,
                                index_text,
                            ) {
                                return result;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// If `child` is a `binary_expression`/`comparison_expression` bound
    /// check against `size` (either a resolved macro constant or a
    /// recognized safe-bounds idiom), return the verdict; `None` means
    /// `child` doesn't carry a bounds check at all, so the caller should
    /// keep looking at its siblings.
    fn condition_child_bounds_verdict(
        &self,
        child: &Node,
        source: &str,
        size: usize,
        macro_constants: &HashMap<String, i64>,
        index_text: &str,
    ) -> Option<bool> {
        if child.kind() != "binary_expression" && child.kind() != "comparison_expression" {
            return None;
        }
        let condition_text = &source[child.start_byte()..child.end_byte()];

        // Check for macro constants in condition (e.g., "j < ROWS")
        if let Some(macro_size) =
            self.extract_and_resolve_macro_from_condition(condition_text, macro_constants)
        {
            // Compare resolved macro value to actual buffer size.
            // If macro value >= buffer size, this is a violation (e.g., j < 7 but buffer is 5).
            return Some(macro_size <= size as i64);
        }

        if self.condition_contains_safe_bounds(condition_text, index_text) {
            return Some(true);
        }

        None
    }

    /// Extract and resolve macro constant from loop condition
    /// For "j < ROWS", extracts "ROWS" and resolves to its value
    fn extract_and_resolve_macro_from_condition(
        &self,
        condition_text: &str,
        macro_constants: &HashMap<String, i64>,
    ) -> Option<i64> {
        // Look for pattern: variable < MACRO or variable <= MACRO
        // Handle both "< MACRO" and "<MACRO" (with or without space)

        // Try "<= " pattern first (more specific)
        if let Some(pos) = condition_text.find("<=") {
            let after_op = &condition_text[pos + 2..].trim_start();
            let macro_name: String = after_op
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();

            if !macro_name.is_empty() {
                if let Some(&value) = macro_constants.get(&macro_name) {
                    // For <=, the effective size is value + 1
                    return Some(value + 1);
                }
                // Try parsing as literal integer (e.g., "i <= 99")
                if let Ok(value) = macro_name.parse::<i64>() {
                    return Some(value + 1);
                }
            }
        }

        // Try "< " pattern
        if let Some(pos) = condition_text.find('<') {
            // Skip if this is <=
            if condition_text.chars().nth(pos + 1) != Some('=') {
                let after_op = &condition_text[pos + 1..].trim_start();
                let macro_name: String = after_op
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();

                if !macro_name.is_empty() {
                    if let Some(&value) = macro_constants.get(&macro_name) {
                        return Some(value);
                    }
                    // Try parsing as literal integer (e.g., "i < 100")
                    if let Ok(value) = macro_name.parse::<i64>() {
                        return Some(value);
                    }
                }
            }
        }

        None
    }

    /// Extract the condition text from an if_statement node (just the parenthesized expression)
    fn extract_if_condition_text(&self, if_node: &Node, source: &str) -> Option<String> {
        for i in 0..if_node.child_count() {
            if let Some(child) = if_node.child(i) {
                if child.kind() == "parenthesized_expression" {
                    return Some(source[child.start_byte()..child.end_byte()].to_string());
                }
            }
        }
        None
    }

    /// Check if statement bounds against specific buffer size
    fn check_if_bounds_against_size(
        &self,
        if_node: &Node,
        source: &str,
        size: usize,
        macro_constants: &HashMap<String, i64>,
    ) -> bool {
        // Extract just the condition from the if-statement, not the full body
        let condition_text = match self.extract_if_condition_text(if_node, source) {
            Some(text) => text,
            None => {
                // Fallback to full text if we can't extract condition
                source[if_node.start_byte()..if_node.end_byte()].to_string()
            }
        };

        // A single-sided `idx < MACRO_NAME` (or a bare `idx < 10`) is just as
        // much a proper bounds guard as the `>=0 && <SOMETHING` pattern below
        // — it doesn't need a paired lower-bound check to be safe against an
        // *upper*-bound overrun, which is all ARR30-C's static-buffer check
        // cares about here. Resolve the macro (or literal) and compare
        // against the real buffer size, exactly like the for-loop path
        // (task 436/443): a `touchSlot < MAX_TOUCH_POINTS` guard on a
        // 10-element buffer is safe whether `touchSlot` is a plain local or
        // a struct field — `extract_and_resolve_macro_from_condition` never
        // looks at the left-hand side, so it already handles both shapes.
        if let Some(bound) =
            self.extract_and_resolve_macro_from_condition(&condition_text, macro_constants)
        {
            return bound <= size as i64;
        }

        // Look for patterns like: if (idx < SIZE) or if (idx < 3)
        if condition_text.contains(&format!("< {}", size)) {
            return true;
        }

        // Also check for macro-based bounds (e.g., "< ROWS", "< COLS")
        // Look for common comparison patterns that indicate bounds checking
        if condition_text.contains("< ")
            && (condition_text.contains(">=") || condition_text.contains("&&"))
        {
            // Pattern like: if (idx >= 0 && idx < SOMETHING)
            // This is a proper bounds check even if we don't know the exact value of SOMETHING
            return true;
        }

        false
    }

    /// Extract the index variable name from a for loop
    /// For loops like `for (int i = 0; i < 10; i++)`, extracts "i"
    fn extract_loop_index_variable(&self, for_node: &Node, source: &str) -> Option<String> {
        // Look for the loop initialization to find the index variable
        for i in 0..for_node.child_count() {
            if let Some(child) = for_node.child(i) {
                // Look for declaration or assignment in loop init
                if child.kind() == "declaration" {
                    // Pattern: int i = 0
                    for j in 0..child.child_count() {
                        if let Some(declarator) = child.child(j) {
                            if declarator.kind() == "init_declarator" {
                                if let Some(identifier) = declarator.child(0) {
                                    if identifier.kind() == "identifier" {
                                        return Some(
                                            source[identifier.start_byte()..identifier.end_byte()]
                                                .to_string(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                } else if child.kind() == "assignment_expression" {
                    // Pattern: i = 0
                    if let Some(left) = child.child(0) {
                        if left.kind() == "identifier" {
                            return Some(source[left.start_byte()..left.end_byte()].to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// Extract buffer allocation from assignment expression
    /// Handles patterns like:
    /// - array[i] = malloc(size * sizeof(type))
    /// - ptr = realloc(ptr, new_size)
    /// - ptr = malloc(size)
    fn extract_buffer_from_assignment(
        &self,
        node: &Node,
        source: &str,
    ) -> Option<(String, BufferInfo)> {
        // Check if this is an assignment with malloc/calloc/realloc on the right side
        let mut left_node: Option<Node> = None;
        let mut right_node: Option<Node> = None;
        let mut found_assign = false;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "=" {
                    found_assign = true;
                } else if !found_assign {
                    left_node = Some(child);
                } else if child.kind() == "call_expression" {
                    right_node = Some(child);
                    break;
                } else if child.kind() == "cast_expression" {
                    // Handle (type *)malloc(...) — unwrap cast to find call_expression
                    if let Some(inner_call) = Self::unwrap_cast_to_call(&child) {
                        right_node = Some(inner_call);
                        break;
                    }
                }
            }
        }

        if !found_assign {
            return None;
        }

        let left = left_node?;
        let right = right_node?;

        // Check if right side is malloc/calloc/realloc
        let func_name_node = right.child(0)?;
        let func_name = &source[func_name_node.start_byte()..func_name_node.end_byte()];

        if !matches!(
            func_name,
            "malloc" | "calloc" | "realloc" | "alloca" | "ALLOCA"
        ) {
            return None;
        }

        // Handle subscript expressions (e.g., matrix[i])
        if left.kind() == "subscript_expression" {
            // Extract the base array name from subscript
            let base_array = self.get_base_array_from_subscript(&left, source)?;

            // Extract allocation size and byte count from malloc/calloc/realloc
            let (buffer_size, alloc_bytes) =
                self.extract_malloc_size_and_bytes_from_call(&right, source)?;

            // Create a wildcard buffer name: base_array[*]
            let buffer_name = format!("{}[*]", base_array);

            let buffer_info = BufferInfo {
                name: buffer_name.clone(),
                size: buffer_size,
                element_type: "unknown".to_string(),
                allocation_line: node.start_position().row + 1,
                alloc_bytes,
            };

            return Some((buffer_name, buffer_info));
        }

        // Handle simple identifier assignments (e.g., ptr = realloc(ptr, new_size))
        if left.kind() == "identifier" {
            let var_name = &source[left.start_byte()..left.end_byte()];

            // Extract allocation size and byte count from malloc/calloc/realloc
            let (buffer_size, alloc_bytes) =
                self.extract_malloc_size_and_bytes_from_call(&right, source)?;

            let buffer_info = BufferInfo {
                name: var_name.to_string(),
                size: buffer_size,
                element_type: "unknown".to_string(),
                allocation_line: node.start_position().row + 1,
                alloc_bytes,
            };

            return Some((var_name.to_string(), buffer_info));
        }

        None
    }

    /// Unwrap cast_expression to find inner call_expression
    /// Handles: (char *)malloc(...), (int *)calloc(...), etc.
    fn unwrap_cast_to_call<'a>(node: &Node<'a>) -> Option<Node<'a>> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "call_expression" {
                    return Some(child);
                }
            }
        }
        None
    }

    /// Get base array name from subscript expression (e.g., "matrix" from "matrix[i]")
    fn get_base_array_from_subscript(&self, node: &Node, source: &str) -> Option<String> {
        let array_node = node.child(0)?;
        if array_node.kind() == "identifier" {
            let text = &source[array_node.start_byte()..array_node.end_byte()];
            return Some(text.to_string());
        } else if array_node.kind() == "subscript_expression" {
            // Nested subscript - recursively get the base name
            // For matrix[i][j], this recursively extracts "matrix"
            return self.get_base_array_from_subscript(&array_node, source);
        }
        None
    }

    /// Get index text from subscript expression
    #[allow(dead_code)]
    fn get_subscript_index_text(&self, node: &Node, source: &str) -> Option<String> {
        let index_node = self.get_subscript_index(node)?;
        let text = &source[index_node.start_byte()..index_node.end_byte()];
        Some(text.to_string())
    }

    /// Extract both element-count size and raw byte count from malloc/calloc/realloc call
    fn extract_malloc_size_and_bytes_from_call(
        &self,
        node: &Node,
        source: &str,
    ) -> Option<(BufferSize, Option<usize>)> {
        // Get function name to determine which argument contains the size
        let func_name_node = node.child(0)?;
        let func_name = &source[func_name_node.start_byte()..func_name_node.end_byte()];

        // Find argument_list
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "argument_list" {
                    // For realloc, the size is the second argument
                    // For malloc/calloc, the size is in the first argument
                    let arg_index = if func_name == "realloc" { 1 } else { 0 };

                    let mut current_arg = 0;
                    for j in 0..child.child_count() {
                        if let Some(arg) = child.child(j) {
                            if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                                if current_arg == arg_index {
                                    let arg_text = &source[arg.start_byte()..arg.end_byte()];
                                    let size = buffer_size::calculate_malloc_size(arg_text)?;
                                    let alloc_bytes = buffer_size::calculate_alloc_bytes(arg_text);
                                    return Some((size, alloc_bytes));
                                }
                                current_arg += 1;
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Get buffer name from a subscript expression for lookup
    /// For matrix[0], tries both "matrix[0]" and "matrix[*]"
    /// Returns the wildcard pattern for now
    fn get_subscript_buffer_name(&self, node: &Node, source: &str) -> Option<String> {
        // Extract base array name
        let base_name = self.get_base_array_from_subscript(node, source)?;

        // Return wildcard pattern for lookup
        Some(format!("{}[*]", base_name))
    }

    /// Check nested subscript expressions (multi-dimensional array access)
    /// For matrix[i][j], checks both:
    /// 1. Is i within bounds of matrix?
    /// 2. Is j within bounds of matrix[i]?
    fn check_nested_subscript(
        &self,
        node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
        aliases: &HashMap<String, PointerAlias>,
        macro_constants: &HashMap<String, i64>,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Get the inner subscript node (matrix[i])
        if let Some(inner_node) = node.child(0) {
            if inner_node.kind() == "subscript_expression" {
                // Step 1: Check the inner subscript bounds (matrix[i])
                violations.extend(self.check_array_subscript(
                    &inner_node,
                    source,
                    buffers,
                    aliases,
                    macro_constants,
                ));

                // Step 2: Get the buffer name for the inner subscript result
                // For matrix[0], this should look up "matrix[*]" in buffers
                if let Some(inner_buffer_name) = self.get_subscript_buffer_name(&inner_node, source)
                {
                    if let Some(inner_buffer) = buffers.get(&inner_buffer_name) {
                        // Step 3: Check the outer index against the inner buffer's size
                        if let Some(outer_index) =
                            self.get_subscript_index_value(node, source, macro_constants)
                        {
                            let is_violation = match &inner_buffer.size {
                                BufferSize::Static(size) | BufferSize::DynamicCalculated(size) => {
                                    match &outer_index {
                                        IndexValue::Constant(idx) => {
                                            *idx < 0 || (*idx as usize) >= *size
                                        }
                                        IndexValue::Expression(_, Some(eval_idx)) => {
                                            *eval_idx < 0 || (*eval_idx as usize) >= *size
                                        }
                                        IndexValue::Expression(expr, None) => {
                                            self.check_expression_bounds(expr, *size)
                                        }
                                        IndexValue::Variable(_var) => {
                                            // Check for bounds validation
                                            !self.has_proper_bounds_check(
                                                node,
                                                source,
                                                *size,
                                                macro_constants,
                                            )
                                        }
                                        IndexValue::Unknown => false,
                                    }
                                }
                                _ => false,
                            };

                            if is_violation {
                                // Get the full array name for error message
                                let full_array_name =
                                    &source[inner_node.start_byte()..inner_node.end_byte()];

                                let msg = Self::oob_message(&outer_index);

                                violations.push(self.create_violation(
                                    node,
                                    full_array_name,
                                    inner_buffer,
                                    &msg,
                                ));
                            }
                        }
                    }
                }
            }
        }

        violations
    }

    /// Create a violation record
    fn create_violation(
        &self,
        node: &Node,
        array_name: &str,
        buffer_info: &BufferInfo,
        message: &str,
    ) -> RuleViolation {
        let start_point = node.start_position();

        let size_info = match &buffer_info.size {
            BufferSize::Static(s) => format!("size {}", s),
            BufferSize::DynamicCalculated(s) => format!("allocated size {}", s),
            BufferSize::Dynamic(expr) => format!("dynamic size ({})", expr),
            BufferSize::Symbolic(var) => format!("VLA size ({})", var),
            BufferSize::Unknown => "unknown size".to_string(),
        };

        RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "{}: Buffer '{}' with {} (allocated at line {})",
                message, array_name, size_info, buffer_info.allocation_line
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(
                "Ensure array access is within allocated bounds. Add explicit bounds checking."
                    .to_string(),
            ),
            ..Default::default()
        }
    }

    /// Check array subscript expressions with buffer size analysis
    fn check_array_subscript(
        &self,
        node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
        aliases: &HashMap<String, PointerAlias>,
        macro_constants: &HashMap<String, i64>,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check if this is a nested subscript expression (e.g., matrix[0][5])
        if let Some(child) = node.child(0) {
            if child.kind() == "subscript_expression" {
                // Delegate to nested subscript handler
                return self.check_nested_subscript(
                    node,
                    source,
                    buffers,
                    aliases,
                    macro_constants,
                );
            }
        }

        if let Some(array_name) = self.get_array_name_from_subscript(node, source) {
            if let Some(index) = self.get_subscript_index_value(node, source, macro_constants) {
                // Check for function parameter violations FIRST, even if buffer not tracked
                // This handles cases like: void func(int arr[], int index) { arr[index]; }
                if let Some(violation) =
                    self.check_unvalidated_param_index(node, source, &index, &array_name)
                {
                    violations.push(violation);
                    return violations;
                }

                // Try to resolve alias first
                let (actual_buffer_name, element_size_bytes) =
                    if let Some(alias) = aliases.get(&array_name) {
                        (alias.original_buffer.as_str(), alias.element_size_bytes)
                    } else {
                        (array_name.as_str(), None)
                    };

                if let Some(buffer_info) = buffers.get(actual_buffer_name) {
                    // Calculate effective buffer size for cast pointers
                    let effective_size =
                        Self::effective_buffer_size(buffer_info, element_size_bytes);

                    let is_violation = self.is_subscript_violation(
                        node,
                        source,
                        &index,
                        buffer_info,
                        effective_size,
                        macro_constants,
                        &array_name,
                    );

                    if is_violation {
                        let msg = Self::oob_message(&index);
                        violations.push(self.create_violation(
                            node,
                            &array_name,
                            buffer_info,
                            &msg,
                        ));
                    }
                }
            }
        }

        violations
    }

    /// If `index` is a bare variable that is an unvalidated function
    /// parameter, build the "unvalidated function parameter index"
    /// violation directly (bypassing buffer-size tracking, since this
    /// applies even when the buffer isn't tracked at all).
    /// Like `ast_utils::is_function_parameter`, but correctly locates the
    /// `function_declarator` even when the function's return type wraps it
    /// in a `pointer_declarator` (e.g. `const char *GetGamepadName(int
    /// gamepad)`). `ast_utils::is_function_parameter` only looks for
    /// `function_declarator` as a *direct* child of the function_definition,
    /// so for a pointer-returning function it silently finds nothing and
    /// reports "not a parameter" — regardless of whether `var_name` really
    /// is one. That made ARR30-C's unvalidated-param-index detection depend
    /// on the *return type* of the enclosing function rather than on the
    /// index expression itself: `CORE.Input.Gamepad.axisCount[gamepad]`
    /// (enclosing function returns `int`) was flagged while the
    /// structurally identical `CORE.Input.Gamepad.name[gamepad]` (enclosing
    /// function returns `char *`) was missed (task 239). Reuses
    /// `find_function_declarator`, which already unwraps one level of
    /// `pointer_declarator` for exactly this reason (see its use in
    /// `check_return_pointer_arith_binary_expr`).
    fn is_function_parameter_any_return(
        &self,
        func_node: &Node,
        var_name: &str,
        source: &str,
    ) -> bool {
        let Some(declarator) = self.find_function_declarator(func_node) else {
            return false;
        };
        let Some(param_list) = find_param_list_node(&declarator) else {
            return false;
        };
        let param_text = &source[param_list.start_byte()..param_list.end_byte()];
        param_text
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|w| w == var_name)
    }

    fn check_unvalidated_param_index(
        &self,
        node: &Node,
        source: &str,
        index: &IndexValue,
        array_name: &str,
    ) -> Option<RuleViolation> {
        let IndexValue::Variable(ref var) = index else {
            return None;
        };
        let func_node = find_containing_function(node)?;
        if !self.is_function_parameter_any_return(&func_node, var, source) {
            return None;
        }
        // Static functions whose index param is a user-defined type (e.g. an
        // enum typedef like led_id_t) have a controlled caller set and
        // enum-constrained values — suppress to avoid FPs.
        if Self::is_static_function(&func_node, source)
            && Self::param_has_user_defined_type(&func_node, var, source)
        {
            return None;
        }
        if self.has_function_parameter_bounds_check(&func_node, var, source) {
            return None;
        }
        if Self::index_is_bounded_by_alloc_roundup(&func_node, array_name, var, source) {
            return None;
        }
        let start_point = node.start_position();
        Some(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "Potentially unsafe array access with unvalidated function parameter index '{}'",
                var
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(
                "Add bounds checking for function parameter before using as array index."
                    .to_string(),
            ),
            ..Default::default()
        })
    }

    /// Is `array_name[var]` provably in-bounds because `array_name` was
    /// allocated to a size that's a "round `var` up to a multiple of `D`,
    /// plus padding" expression of `var` itself (task 446)?
    ///
    /// This is the classic MD5/SHA1-style hash padding idiom:
    /// ```c
    /// int newDataSize = ((((dataSize + K1) / D) + C) * D) - K2;
    /// unsigned char *msg = RL_CALLOC(newDataSize + K_OUTER, 1);
    /// msg[dataSize] = 128;
    /// ```
    /// sqc has no preprocessor and doesn't track `RL_CALLOC`/similar aliases
    /// as allocation calls at all, so `msg` was never a tracked buffer and
    /// this rule fell through to the generic "unvalidated function parameter
    /// index" check, which knows nothing about the allocation. Rather than
    /// widen buffer tracking to arbitrary macro-aliased allocators (a much
    /// bigger, riskier change), this proves the specific inequality that
    /// makes the access safe: for any non-negative integer `var`,
    /// `floor((var + K1) / D) * D` is always strictly greater than
    /// `var + K1 - D`, so the surrounding `+ C`, `* D`, `- K2`, `+ K_OUTER`
    /// terms are safe exactly when `K1 + D*(C-1) + K_OUTER >= K2` — see the
    /// derivation in `match_roundup_formula`'s doc comment. Any allocation
    /// shape that doesn't match this exact algebraic pattern returns `false`
    /// (still flagged), so this can only suppress, never miss, a violation.
    fn index_is_bounded_by_alloc_roundup(
        func_node: &Node,
        array_name: &str,
        var: &str,
        source: &str,
    ) -> bool {
        let Some(size_arg) = Self::find_alloc_size_arg_for_var(func_node, array_name, source)
        else {
            return false;
        };
        let Some((top_ident, k_outer)) = Self::split_ident_plus_const(&size_arg, source) else {
            return false;
        };
        if top_ident == var {
            // Direct subterm case: `calloc(var + k_outer, ...)` -- safe iff
            // the padding is strictly positive.
            return k_outer >= 1;
        }
        let Some(inner_expr) = Self::find_local_init_expr(func_node, &top_ident, source) else {
            return false;
        };
        if let Some((k1, d, c, k2)) = Self::match_roundup_formula(&inner_expr, var, source) {
            if d <= 0 {
                return false;
            }
            return k1 + d * (c - 1) + k_outer >= k2;
        }
        // Fall back to the two-statement mod-based round-up idiom (task 448),
        // e.g. SHA-256-style padding, which `match_roundup_formula` can't
        // match since it's a single-expression div-mul pattern.
        k_outer >= 0
            && Self::expr_is_var_plus_nonneg(&inner_expr, var, source)
            && Self::has_mod_roundup_followup(func_node, &top_ident, source)
    }

    /// Does `expr` reduce to `var`, `var + K` (a literal `K >= 0`), or
    /// `var + sizeof(...)` (any `sizeof` is always `>= 1`, so its exact
    /// value doesn't matter for the non-negativity proof this feeds)?
    fn expr_is_var_plus_nonneg(node: &Node, var: &str, source: &str) -> bool {
        let node = Self::strip_parens(node);
        let is_var =
            |n: &Node| n.kind() == "identifier" && &source[n.start_byte()..n.end_byte()] == var;
        if is_var(&node) {
            return true;
        }
        if node.kind() != "binary_expression" {
            return false;
        }
        let Some(op) = node.child_by_field_name("operator") else {
            return false;
        };
        if &source[op.start_byte()..op.end_byte()] != "+" {
            return false;
        }
        let Some(lhs) = node.child_by_field_name("left") else {
            return false;
        };
        let Some(rhs) = node.child_by_field_name("right") else {
            return false;
        };
        let lhs = Self::strip_parens(&lhs);
        let rhs = Self::strip_parens(&rhs);
        let is_nonneg_const = |n: &Node| match n.kind() {
            "sizeof_expression" => true,
            _ => Self::parse_int_literal(n, source).is_some_and(|k| k >= 0),
        };
        (is_var(&lhs) && is_nonneg_const(&rhs)) || (is_var(&rhs) && is_nonneg_const(&lhs))
    }

    /// Find, anywhere in `func_node`, a `tmp += (D - (tmp % D))` or
    /// `tmp = tmp + (D - (tmp % D))` statement for `tmp` -- the mod-based
    /// round-up-to-a-multiple-of-`D` idiom. `D - (tmp % D)` is always in
    /// `[1, D]` (when `tmp % D == 0`, the full `D` is added, never `0`), so
    /// matching this shape proves the statement always strictly increases
    /// `tmp`, regardless of `D`'s concrete value.
    fn has_mod_roundup_followup(func_node: &Node, tmp: &str, source: &str) -> bool {
        let mut found = false;
        Self::walk_for_mod_roundup_followup(func_node, tmp, source, &mut found);
        found
    }

    fn walk_for_mod_roundup_followup(node: &Node, tmp: &str, source: &str, found: &mut bool) {
        if *found {
            return;
        }
        if node.kind() == "assignment_expression" {
            if let (Some(left), Some(op), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("operator"),
                node.child_by_field_name("right"),
            ) {
                let op_text = &source[op.start_byte()..op.end_byte()];
                let left_is_tmp = left.kind() == "identifier"
                    && &source[left.start_byte()..left.end_byte()] == tmp;
                if left_is_tmp {
                    let addend = match op_text {
                        "+=" => Some(right),
                        "=" => Self::extract_self_addend(&right, tmp, source),
                        _ => None,
                    };
                    if let Some(addend) = addend {
                        if Self::is_mod_roundup_addend(&addend, tmp, source) {
                            *found = true;
                            return;
                        }
                    }
                }
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                Self::walk_for_mod_roundup_followup(&child, tmp, source, found);
                if *found {
                    return;
                }
            }
        }
    }

    /// Match `tmp + X` or `X + tmp` -> `X` (the non-`tmp` addend), for the
    /// `tmp = tmp + X` self-reassignment form.
    fn extract_self_addend<'a>(node: &Node<'a>, tmp: &str, source: &str) -> Option<Node<'a>> {
        let node = Self::strip_parens(node);
        if node.kind() != "binary_expression" {
            return None;
        }
        let op = node.child_by_field_name("operator")?;
        if &source[op.start_byte()..op.end_byte()] != "+" {
            return None;
        }
        let lhs = Self::strip_parens(&node.child_by_field_name("left")?);
        let rhs = Self::strip_parens(&node.child_by_field_name("right")?);
        let is_tmp =
            |n: &Node| n.kind() == "identifier" && &source[n.start_byte()..n.end_byte()] == tmp;
        if is_tmp(&lhs) {
            return Some(rhs);
        }
        if is_tmp(&rhs) {
            return Some(lhs);
        }
        None
    }

    /// Does `addend` match `D - (tmp % D)` for some positive integer literal
    /// `D`?
    fn is_mod_roundup_addend(addend: &Node, tmp: &str, source: &str) -> bool {
        let addend = Self::strip_parens(addend);
        if addend.kind() != "binary_expression" {
            return false;
        }
        let Some(op) = addend.child_by_field_name("operator") else {
            return false;
        };
        if &source[op.start_byte()..op.end_byte()] != "-" {
            return false;
        }
        let Some(lhs) = addend.child_by_field_name("left") else {
            return false;
        };
        let Some(rhs) = addend.child_by_field_name("right") else {
            return false;
        };
        let Some(d) = Self::parse_int_literal(&Self::strip_parens(&lhs), source) else {
            return false;
        };
        if d <= 0 {
            return false;
        }
        let rhs = Self::strip_parens(&rhs);
        if rhs.kind() != "binary_expression" {
            return false;
        }
        let Some(mod_op) = rhs.child_by_field_name("operator") else {
            return false;
        };
        if &source[mod_op.start_byte()..mod_op.end_byte()] != "%" {
            return false;
        }
        let Some(mod_lhs) = rhs.child_by_field_name("left") else {
            return false;
        };
        let Some(mod_rhs) = rhs.child_by_field_name("right") else {
            return false;
        };
        let mod_lhs = Self::strip_parens(&mod_lhs);
        if mod_lhs.kind() != "identifier"
            || &source[mod_lhs.start_byte()..mod_lhs.end_byte()] != tmp
        {
            return false;
        }
        Self::parse_int_literal(&Self::strip_parens(&mod_rhs), source) == Some(d)
    }

    /// Find the size argument of the allocation call that initializes
    /// `array_name` somewhere in `func_node` (init_declarator or plain
    /// assignment, optionally through a pointer cast). Matches any call
    /// whose function name contains "alloc"/"ALLOC" -- this is intentionally
    /// broad (covers `malloc`/`calloc`/`realloc`/`alloca` and macro aliases
    /// like `RL_MALLOC`/`RL_CALLOC` that sqc has no preprocessor to resolve)
    /// since an accidental match on an unrelated function only feeds into
    /// `match_roundup_formula`'s exact algebraic pattern match, which will
    /// simply fail to match and change nothing.
    fn find_alloc_size_arg_for_var<'a>(
        func_node: &Node<'a>,
        array_name: &str,
        source: &str,
    ) -> Option<Node<'a>> {
        let mut result = None;
        Self::walk_for_alloc_size_arg(func_node, array_name, source, &mut result);
        result
    }

    fn walk_for_alloc_size_arg<'a>(
        node: &Node<'a>,
        array_name: &str,
        source: &str,
        result: &mut Option<Node<'a>>,
    ) {
        if result.is_some() {
            return;
        }
        let lhs_name = match node.kind() {
            "init_declarator" => node
                .child_by_field_name("declarator")
                .map(|d| get_identifier_from_declarator(&d, source)),
            "assignment_expression" => node
                .child_by_field_name("left")
                .filter(|l| l.kind() == "identifier")
                .map(|l| source[l.start_byte()..l.end_byte()].to_string()),
            _ => None,
        };
        if lhs_name.as_deref() == Some(array_name) {
            if let Some(value) = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("right"))
            {
                let call = if value.kind() == "call_expression" {
                    Some(value)
                } else if value.kind() == "cast_expression" {
                    Self::unwrap_cast_to_call(&value)
                } else {
                    None
                };
                if let Some(call) = call {
                    if let Some(size_arg) = Self::alloc_call_size_arg(&call, source) {
                        *result = Some(size_arg);
                        return;
                    }
                }
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                Self::walk_for_alloc_size_arg(&child, array_name, source, result);
                if result.is_some() {
                    return;
                }
            }
        }
    }

    /// Pick out the argument of an alloc-like call that represents the total
    /// byte count, given its arity/name: `malloc(size)`/`alloca(size)` ->
    /// the sole argument; `realloc(ptr, size)` -> the 2nd argument;
    /// `calloc(count, elem_size)` -> the count, but only when `elem_size` is
    /// the literal `1` (otherwise the byte count isn't `count` alone, and
    /// this is out of scope).
    fn alloc_call_size_arg<'a>(call: &Node<'a>, source: &str) -> Option<Node<'a>> {
        let func_name_node = call.child(0)?;
        if func_name_node.kind() != "identifier" {
            return None;
        }
        let func_name = &source[func_name_node.start_byte()..func_name_node.end_byte()];
        if !func_name.to_ascii_uppercase().contains("ALLOC") {
            return None;
        }
        let arg_list = call.child_by_field_name("arguments")?;
        let args: Vec<Node> = (0..arg_list.child_count())
            .filter_map(|i| arg_list.child(i))
            .filter(|c| !matches!(c.kind(), "(" | ")" | ","))
            .collect();
        match args.len() {
            1 => Some(args[0]),
            2 if func_name.to_ascii_uppercase().contains("REALLOC") => Some(args[1]),
            2 => {
                let elem_text = source[args[1].start_byte()..args[1].end_byte()].trim();
                // `sizeof(char)`/`sizeof(unsigned char)`/`sizeof(signed char)`
                // are also always 1, same as a literal `1` (task 448).
                let is_size_one = elem_text == "1"
                    || matches!(
                        elem_text
                            .strip_prefix("sizeof(")
                            .and_then(|s| s.strip_suffix(')'))
                            .map(str::trim),
                        Some("char") | Some("unsigned char") | Some("signed char")
                    );
                is_size_one.then_some(args[0])
            }
            _ => None,
        }
    }

    /// Find `name`'s own initializer expression from a local declaration
    /// inside `func_node` (one level of variable indirection).
    fn find_local_init_expr<'a>(
        func_node: &Node<'a>,
        name: &str,
        source: &str,
    ) -> Option<Node<'a>> {
        let mut result = None;
        Self::walk_for_local_init_expr(func_node, name, source, &mut result);
        result
    }

    fn walk_for_local_init_expr<'a>(
        node: &Node<'a>,
        name: &str,
        source: &str,
        result: &mut Option<Node<'a>>,
    ) {
        if result.is_some() {
            return;
        }
        if node.kind() == "init_declarator" {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                if get_identifier_from_declarator(&declarator, source) == name {
                    *result = node.child_by_field_name("value");
                    if result.is_some() {
                        return;
                    }
                }
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                Self::walk_for_local_init_expr(&child, name, source, result);
                if result.is_some() {
                    return;
                }
            }
        }
    }

    /// Strip redundant `parenthesized_expression` wrappers.
    fn strip_parens<'a>(node: &Node<'a>) -> Node<'a> {
        let mut n = *node;
        while n.kind() == "parenthesized_expression" {
            let Some(inner) = (0..n.child_count())
                .filter_map(|i| n.child(i))
                .find(|c| !matches!(c.kind(), "(" | ")"))
            else {
                break;
            };
            n = inner;
        }
        n
    }

    /// Match `IDENT`, `IDENT + K`, `K + IDENT`, or `IDENT - K` -> `(IDENT, K)`
    /// (with `K = 0` for the bare-identifier case).
    fn split_ident_plus_const(node: &Node, source: &str) -> Option<(String, i64)> {
        let node = Self::strip_parens(node);
        if node.kind() == "identifier" {
            return Some((source[node.start_byte()..node.end_byte()].to_string(), 0));
        }
        if node.kind() != "binary_expression" {
            return None;
        }
        let op = node.child_by_field_name("operator")?;
        let op_text = &source[op.start_byte()..op.end_byte()];
        if op_text != "+" && op_text != "-" {
            return None;
        }
        let lhs = Self::strip_parens(&node.child_by_field_name("left")?);
        let rhs = Self::strip_parens(&node.child_by_field_name("right")?);
        if lhs.kind() == "identifier" {
            let k = Self::parse_int_literal(&rhs, source)?;
            let k = if op_text == "-" { -k } else { k };
            return Some((source[lhs.start_byte()..lhs.end_byte()].to_string(), k));
        }
        if op_text == "+" && rhs.kind() == "identifier" {
            let k = Self::parse_int_literal(&lhs, source)?;
            return Some((source[rhs.start_byte()..rhs.end_byte()].to_string(), k));
        }
        None
    }

    fn parse_int_literal(node: &Node, source: &str) -> Option<i64> {
        if node.kind() != "number_literal" {
            return None;
        }
        source[node.start_byte()..node.end_byte()]
            .trim()
            .parse::<i64>()
            .ok()
    }

    /// Match a `binary_expression` with operator `op` where one side is an
    /// integer literal, returning `(other_side, literal_value)`. For `+`/`*`
    /// (commutative) either side may hold the literal; for `-`/`/`
    /// (`rhs_only`), only the right-hand side may, since `X - K` and `K - X`
    /// (likewise `X / K` vs `K / X`) are not interchangeable.
    fn match_binary_with_const<'a>(
        node: &Node<'a>,
        op: &str,
        rhs_only: bool,
        source: &str,
    ) -> Option<(Node<'a>, i64)> {
        if node.kind() != "binary_expression" {
            return None;
        }
        let op_node = node.child_by_field_name("operator")?;
        if &source[op_node.start_byte()..op_node.end_byte()] != op {
            return None;
        }
        let lhs = Self::strip_parens(&node.child_by_field_name("left")?);
        let rhs = Self::strip_parens(&node.child_by_field_name("right")?);
        if let Some(k) = Self::parse_int_literal(&rhs, source) {
            return Some((lhs, k));
        }
        if !rhs_only {
            if let Some(k) = Self::parse_int_literal(&lhs, source) {
                return Some((rhs, k));
            }
        }
        None
    }

    /// Match the round-up-to-a-multiple allocation-size idiom against `var`:
    /// `( ( (var [+ K1]) / D ) [+ C] ) * D  [- K2]` -> `(K1, D, C, K2)`
    /// (`K1`/`C`/`K2` default to 0 when the corresponding term is absent).
    ///
    /// Soundness argument: floor division means `(var + K1) / D * D` is
    /// always in `(var + K1 - D, var + K1]`, so
    /// `((var + K1) / D + C) * D` is always in
    /// `(var + K1 - D + C*D, var + K1 + C*D]`. Subtracting `K2` and adding
    /// the caller's own `K_OUTER` (from `split_ident_plus_const` on the
    /// allocation's top-level size argument) shifts that lower bound to
    /// `var + K1 - D + C*D - K2 + K_OUTER` (exclusive), which strictly
    /// exceeds `var` exactly when `K1 + D*(C-1) + K_OUTER >= K2` -- the
    /// condition checked by the caller.
    fn match_roundup_formula(node: &Node, var: &str, source: &str) -> Option<(i64, i64, i64, i64)> {
        let node = Self::strip_parens(node);
        let (mul_part, k2) = match Self::match_binary_with_const(&node, "-", true, source) {
            Some((lhs, k)) => (lhs, k),
            None => (node, 0),
        };
        let mul_part = Self::strip_parens(&mul_part);
        let (mid, d) = Self::match_binary_with_const(&mul_part, "*", false, source)?;
        let mid = Self::strip_parens(&mid);
        let (div_part, c) = match Self::match_binary_with_const(&mid, "+", false, source) {
            Some((other, k)) => (other, k),
            None => (mid, 0),
        };
        let div_part = Self::strip_parens(&div_part);
        let (numer, d2) = Self::match_binary_with_const(&div_part, "/", true, source)?;
        if d2 != d {
            return None;
        }
        let (ident, k1) = Self::split_ident_plus_const(&numer, source)?;
        if ident != var {
            return None;
        }
        Some((k1, d, c, k2))
    }

    /// Convert a tracked buffer's byte/element size into the effective
    /// element count for bounds checks, accounting for cast-pointer aliases
    /// (whose size is tracked in bytes of a different element type).
    fn effective_buffer_size(buffer_info: &BufferInfo, element_size_bytes: Option<usize>) -> usize {
        match &buffer_info.size {
            BufferSize::Static(size) | BufferSize::DynamicCalculated(size) => {
                match element_size_bytes {
                    Some(elem_bytes) => size / elem_bytes,
                    None => *size,
                }
            }
            _ => 0, // Handled separately per BufferSize variant below
        }
    }

    /// Dispatch bounds-violation detection by the buffer's size-tracking kind.
    fn is_subscript_violation(
        &self,
        node: &Node,
        source: &str,
        index: &IndexValue,
        buffer_info: &BufferInfo,
        effective_size: usize,
        macro_constants: &HashMap<String, i64>,
        buffer_name: &str,
    ) -> bool {
        match &buffer_info.size {
            BufferSize::Static(_) | BufferSize::DynamicCalculated(_) => self
                .is_fixed_size_violation(
                    node,
                    source,
                    index,
                    effective_size,
                    macro_constants,
                    buffer_name,
                ),
            BufferSize::Symbolic(size_var) => self.is_symbolic_size_violation(index, size_var),
            BufferSize::Dynamic(_) => match index {
                IndexValue::Variable(_) | IndexValue::Expression(_, None) => {
                    !self.has_dynamic_bounds_check(node, source)
                }
                _ => false,
            },
            BufferSize::Unknown => false,
        }
    }

    /// Bounds check for statically/dynamically-calculated fixed-size buffers.
    fn is_fixed_size_violation(
        &self,
        node: &Node,
        source: &str,
        index: &IndexValue,
        effective_size: usize,
        macro_constants: &HashMap<String, i64>,
        buffer_name: &str,
    ) -> bool {
        match index {
            IndexValue::Constant(idx) => {
                // Constant index access - check for negative indices OR out of bounds
                *idx < 0 || (*idx as usize) >= effective_size
            }
            IndexValue::Expression(_, Some(eval_idx)) => {
                // Expression evaluated to constant - check bounds
                *eval_idx < 0 || (*eval_idx as usize) >= effective_size
            }
            IndexValue::Expression(expr, None) => {
                // Expression with variable component - analyze it
                self.check_expression_bounds(expr, effective_size)
            }
            IndexValue::Variable(var) => self.is_fixed_size_variable_index_violation(
                node,
                source,
                var,
                effective_size,
                macro_constants,
                buffer_name,
            ),
            IndexValue::Unknown => false,
        }
    }

    /// Bounds check for a bare-variable index into a fixed-size buffer: VRA
    /// proof, recursive-modification heuristic, then parameter/general
    /// bounds-check fallbacks.
    fn is_fixed_size_variable_index_violation(
        &self,
        node: &Node,
        source: &str,
        var: &str,
        effective_size: usize,
        macro_constants: &HashMap<String, i64>,
        buffer_name: &str,
    ) -> bool {
        // VRA suppression: if VRA proves index in [0, size-1], safe.
        let vra_safe = self
            .vra_var_ranges_at(node)
            .and_then(|ranges| ranges.get(var).copied())
            .map(|range| range.min >= 0 && (range.max as usize) < effective_size)
            .unwrap_or(false);
        if vra_safe {
            return false;
        }
        // Pointer-aliasing constant resolution (task 206): an additional
        // proof source alongside VRA, for patterns VRA can't model at all
        // (VRA has zero pointer-dereference modeling) — write-then-read
        // through an aliased pointer (`*dataPtr1 = data; ... *dataPtr2`,
        // both pointing at the same storage). Deliberately additive-only:
        // if the resolved value is itself out of range, this does NOT
        // short-circuit to "violation" — a resolved-but-out-of-range value
        // may still be correctly guarded by a surrounding `if`, which
        // `has_proper_bounds_check` below already handles (e.g. Juliet's
        // `goodB2G` variant); it just falls through exactly as before this
        // check existed.
        let alias_safe = self
            .resolve_value_of_identifier_at(var, node, source, 0)
            .map(|v| v >= 0 && (v as usize) < effective_size)
            .unwrap_or(false);
        if alias_safe {
            return false;
        }
        // recv()/read()-family return-value proof (task 434): a third proof
        // source alongside VRA and alias resolution above, for the Juliet
        // CWE-789 boilerplate idiom `recvResult = recv(sock, inputBuffer,
        // CHAR_ARRAY_SIZE - 1, 0); ... inputBuffer[recvResult] = '\0';`. The
        // return value of a bounded-read call against a given buffer and
        // length argument can never exceed that length -- safe by
        // construction, not by a runtime check VRA/alias resolution could see.
        if self.is_bounded_by_read_call_length(
            var,
            node,
            source,
            buffer_name,
            effective_size,
            macro_constants,
        ) {
            return false;
        }
        if self.has_recursive_index_modification(node, var, source, effective_size) {
            return true;
        }
        if let Some(func_node) = find_containing_function(node) {
            if self.is_function_parameter_any_return(&func_node, var, source)
                && !(Self::is_static_function(&func_node, source)
                    && Self::param_has_user_defined_type(&func_node, var, source))
            {
                return !self.has_function_parameter_bounds_check(&func_node, var, source);
            }
        }
        !self.has_proper_bounds_check(node, source, effective_size, macro_constants)
    }

    /// True if `var`'s value is provably bounded by a same-buffer
    /// `recv()`/`read()`-family call's own length argument:
    /// `var = recv(fd, buf, len_expr, flags)` (or `read(fd, buf, len_expr)`)
    /// where `buf` is textually the same buffer being indexed and
    /// `len_expr` evaluates to a constant `<= effective_size`. Such a
    /// call's return value can never exceed the length it was given
    /// against that exact buffer (task 434).
    ///
    /// Searches the whole enclosing function (not just `var`'s own
    /// declaration-scope block, unlike `find_last_assigned_value_expr`):
    /// Juliet's `do { ... recvResult = recv(...); ... } while (0);`
    /// idiom assigns inside a nested compound statement one level below
    /// `recvResult`'s own declaration block, which a same-block-only scan
    /// would never see.
    fn is_bounded_by_read_call_length(
        &self,
        var: &str,
        node: &Node,
        source: &str,
        buffer_name: &str,
        effective_size: usize,
        macro_constants: &HashMap<String, i64>,
    ) -> bool {
        const BOUNDED_RETURN_CALLS: &[&str] = &["recv", "read", "recvfrom", "pread"];

        let Some(func_node) = find_containing_function(node) else {
            return false;
        };

        let mut found = false;
        Self::for_each_descendant(&func_node, &mut |n| {
            if found || n.kind() != "assignment_expression" || n.start_byte() >= node.start_byte() {
                return;
            }
            let Some(left) = n.child_by_field_name("left") else {
                return;
            };
            if left.kind() != "identifier" || &source[left.start_byte()..left.end_byte()] != var {
                return;
            }
            let Some(value_node) = n.child_by_field_name("right") else {
                return;
            };
            if value_node.kind() != "call_expression" {
                return;
            }
            let Some(function_node) = value_node.child_by_field_name("function") else {
                return;
            };
            let func_name = source[function_node.start_byte()..function_node.end_byte()].trim();
            if !BOUNDED_RETURN_CALLS.contains(&func_name) {
                return;
            }
            let Some(arguments) = value_node.child_by_field_name("arguments") else {
                return;
            };
            let mut cursor = arguments.walk();
            let args: Vec<Node> = arguments.named_children(&mut cursor).collect();
            // recv(fd, buf, len, flags) / read(fd, buf, len) / recvfrom(fd,
            // buf, len, flags, addr, addrlen) / pread(fd, buf, len, offset)
            // -- the buffer is always arg 1, the length is always arg 2.
            let (Some(buf_arg), Some(len_arg)) = (args.get(1), args.get(2)) else {
                return;
            };
            let buf_text = source[buf_arg.start_byte()..buf_arg.end_byte()].trim();
            if buf_text != buffer_name {
                return;
            }
            found = const_eval::try_evaluate_expr(len_arg, source, macro_constants)
                .map(|v| v >= 0 && (v as usize) <= effective_size)
                .unwrap_or(false);
        });
        found
    }

    /// VLA-with-symbolic-size bounds check: only catches provably
    /// out-of-bounds patterns (exact match on the size variable, or a
    /// statically-known offset from it).
    fn is_symbolic_size_violation(&self, index: &IndexValue, size_var: &str) -> bool {
        match index {
            IndexValue::Variable(var) => {
                // Check if var == size_var (e.g., vla[n] when size is n)
                // This is always out of bounds (valid range: 0 to n-1)
                var == size_var
            }
            IndexValue::Expression(expr, _) => {
                // Check for symbolic violations like "n + 5" when size is "n"
                self.check_symbolic_bounds(expr, size_var)
            }
            IndexValue::Constant(idx) => {
                // Negative index is always invalid
                *idx < 0
            }
            IndexValue::Unknown => false,
        }
    }

    /// Build the out-of-bounds diagnostic message for a violating index.
    fn oob_message(index: &IndexValue) -> String {
        match index {
            IndexValue::Constant(idx) => format!("Out-of-bounds array access at index {}", idx),
            IndexValue::Expression(expr, Some(eval_idx)) => format!(
                "Out-of-bounds array access: '{}' evaluates to {}",
                expr, eval_idx
            ),
            IndexValue::Expression(expr, None) => {
                format!("Potentially unsafe array access with expression '{}'", expr)
            }
            IndexValue::Variable(var) => format!(
                "Potentially unsafe array access with variable index '{}'",
                var
            ),
            IndexValue::Unknown => "Potentially unsafe array access".to_string(),
        }
    }

    /// Check if an expression with variables could cause out-of-bounds access
    /// For expressions like "var + 5", if constant >= size, it's always unsafe
    fn check_expression_bounds(&self, expr: &str, size: usize) -> bool {
        // Pattern: var + const or const + var
        if expr.contains('+') {
            let parts: Vec<&str> = expr.split('+').collect();
            if parts.len() == 2 {
                // Try to extract the constant part
                for part in parts {
                    if let Ok(const_offset) = part.trim().parse::<usize>() {
                        // If constant offset >= size, ANY value of var causes overflow
                        // (even var = 0 would result in index >= size)
                        if const_offset >= size {
                            return true;
                        }
                    }
                }
            }
        }

        // Pattern: var - const (less common but possible)
        // This is generally safer, so we don't flag without more context

        // For other expressions, require bounds checking
        false
    }

    /// Check symbolic bounds for VLA expressions
    /// Returns true if the expression is provably out of bounds
    fn check_symbolic_bounds(&self, index_expr: &str, size_var: &str) -> bool {
        let expr = index_expr.trim();

        // Pattern 1: size_var + constant (where constant > 0)
        // e.g., "n + 5" when size is "n" - ALWAYS out of bounds
        if expr.contains('+') {
            let parts: Vec<&str> = expr.split('+').collect();
            if parts.len() == 2 {
                let (part1, part2) = (parts[0].trim(), parts[1].trim());

                // Check if one part is size_var and other is positive constant
                if part1 == size_var {
                    if let Ok(offset) = part2.parse::<isize>() {
                        return offset > 0; // ALWAYS out of bounds
                    }
                } else if part2 == size_var {
                    if let Ok(offset) = part1.parse::<isize>() {
                        return offset > 0;
                    }
                }
            }
        }

        // Pattern 2: index == size_var (e.g., vla[n] when size is n)
        // This is out of bounds (valid range: 0 to n-1)
        if expr == size_var {
            return true;
        }

        // Pattern 3: size_var - constant (where constant < 0 would be a problem)
        // e.g., "n - 1" when size is "n" is VALID (last element)
        // We don't flag this as it's generally safe

        false
    }

    /// Check pointer arithmetic for bounds violations
    fn check_pointer_arithmetic(
        &self,
        node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
        aliases: &HashMap<String, PointerAlias>,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        if let Some((ptr_name, offset)) = self.extract_pointer_arithmetic(node, source) {
            // Try to resolve alias first
            let (actual_buffer_name, element_size_bytes) =
                if let Some(alias) = aliases.get(&ptr_name) {
                    (alias.original_buffer.as_str(), alias.element_size_bytes)
                } else {
                    (ptr_name.as_str(), None)
                };

            if let Some(buffer_info) = buffers.get(actual_buffer_name) {
                match &buffer_info.size {
                    BufferSize::Static(size) | BufferSize::DynamicCalculated(size) => {
                        if let OffsetValue::Constant(off) = offset {
                            // Calculate effective buffer size in elements
                            let effective_size = if let Some(elem_bytes) = element_size_bytes {
                                // For cast pointers, convert byte size to element count
                                // buffer is malloc(16), cast to int* (4 bytes) = 4 ints
                                size / elem_bytes
                            } else {
                                // No cast, use size as-is
                                *size
                            };

                            if off >= effective_size {
                                let msg = format!(
                                    "Pointer arithmetic moves {} elements beyond buffer bounds (effective size: {})",
                                    off, effective_size
                                );
                                violations.push(self.create_violation(
                                    node,
                                    &ptr_name,
                                    buffer_info,
                                    &msg,
                                ));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        violations
    }

    /// Check for pointer arithmetic in return statements
    /// Detects patterns like: return buffer + index (where index can be negative)
    fn check_return_pointer_arithmetic(
        &self,
        return_node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
        aliases: &HashMap<String, PointerAlias>,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Look for binary_expression children (e.g., "buffer + offset")
        for i in 0..return_node.child_count() {
            let Some(child) = return_node.child(i) else {
                continue;
            };
            if child.kind() != "binary_expression" {
                continue;
            }
            if let Some(violation) = self.check_return_pointer_arith_binary_expr(
                &child,
                return_node,
                source,
                buffers,
                aliases,
            ) {
                violations.push(violation);
            }
        }

        violations
    }

    /// Check a single `buffer + offset` (or `offset + buffer`) binary
    /// expression found in a return statement for an unchecked signed
    /// offset parameter.
    fn check_return_pointer_arith_binary_expr(
        &self,
        child: &Node,
        return_node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
        aliases: &HashMap<String, PointerAlias>,
    ) -> Option<RuleViolation> {
        let (left_name, right_name) = self.extract_binary_expr_operands(child, source)?;
        let offset = Self::resolve_pointer_arith_offset(&left_name, &right_name, buffers, aliases)?;

        // Check if offset is a signed function parameter without lower bound check
        let func_node = find_containing_function(return_node)?;
        // Extract the function_declarator from within the function_definition
        // (it may be nested inside a pointer_declarator for pointer return types)
        let func_declarator = self.find_function_declarator(&func_node)?;
        let param_decl = Self::find_matching_param_declaration(&func_declarator, offset, source)?;

        let param_text = &source[param_decl.start_byte()..param_decl.end_byte()];
        // Check if the type is signed (int, long, ssize_t, etc.)
        let is_signed = param_text.contains("int ")
            && !param_text.contains("unsigned")
            && !param_text.contains("size_t");
        if !is_signed || self.has_lower_bound_check(&func_node, offset, source) {
            return None;
        }

        let start_point = child.start_position();
        Some(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "Pointer arithmetic with signed parameter '{}' that lacks lower bound check (>= 0). Negative values cause undefined behavior.",
                offset
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(format!(
                "Add check: if ({} >= 0 && {} < size)",
                offset, offset
            )),
            ..Default::default()
        })
    }

    /// Given the two operand names of a `a + b` expression, determine which
    /// one is a tracked buffer (resolving aliases) and return the name of
    /// the other operand (the pointer-arithmetic offset), in whichever
    /// order they appeared.
    fn resolve_pointer_arith_offset<'a>(
        left_name: &'a str,
        right_name: &'a str,
        buffers: &HashMap<String, BufferInfo>,
        aliases: &HashMap<String, PointerAlias>,
    ) -> Option<&'a str> {
        let resolve = |name: &str| -> String {
            aliases
                .get(name)
                .map(|alias| alias.original_buffer.clone())
                .unwrap_or_else(|| name.to_string())
        };
        if buffers.contains_key(&resolve(left_name)) {
            return Some(right_name);
        }
        if buffers.contains_key(&resolve(right_name)) {
            return Some(left_name);
        }
        None
    }

    /// Find the `parameter_declaration` inside `func_declarator`'s
    /// `parameter_list` whose text mentions `offset` by name.
    fn find_matching_param_declaration<'a>(
        func_declarator: &Node<'a>,
        offset: &str,
        source: &str,
    ) -> Option<Node<'a>> {
        for j in 0..func_declarator.child_count() {
            let param_list = func_declarator.child(j)?;
            if param_list.kind() != "parameter_list" {
                continue;
            }
            for k in 0..param_list.child_count() {
                let Some(param_decl) = param_list.child(k) else {
                    continue;
                };
                if param_decl.kind() != "parameter_declaration" {
                    continue;
                }
                let param_text = &source[param_decl.start_byte()..param_decl.end_byte()];
                if param_text.contains(offset) {
                    return Some(param_decl);
                }
            }
        }
        None
    }

    /// Check while loops for unbounded pointer increment
    /// Detects patterns like: while (*ptr != delim) *dest++ = *src++;
    fn check_while_loop_pointer_increment(
        &self,
        while_node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        let (Some(condition), Some(body)) = (
            while_node.child_by_field_name("condition"),
            while_node.child_by_field_name("body"),
        ) else {
            return violations;
        };

        // Genuine `identifier++`/`++identifier`/`identifier--`/`--identifier`
        // updates in the loop body — walking update_expression nodes instead
        // of substring-scanning the body's raw text means a comment or
        // string literal mentioning "++" can't fake an increment.
        let incremented_pointers: Vec<String> =
            query::find_descendants_of_kind(body, "update_expression")
                .iter()
                .filter(|u| {
                    u.child_by_field_name("operator").is_some_and(|o| {
                        matches!(&source[o.start_byte()..o.end_byte()], "++" | "--")
                    })
                })
                .filter_map(|u| u.child_by_field_name("argument"))
                .map(|arg| source[arg.start_byte()..arg.end_byte()].to_string())
                .collect();

        if incremented_pointers.is_empty() {
            return violations; // No pointer increment, safe
        }

        // Check if there's bounds checking in the condition: a genuine
        // relational comparison, or a reference to a bound/limit-named
        // variable — matched against the condition's own binary_expression
        // operators and identifier nodes, not its raw text, so a comment or
        // unrelated string literal can't fake a bounds check.
        let has_relational_comparison =
            query::find_descendants_of_kind(condition, "binary_expression")
                .iter()
                .any(|cmp| {
                    cmp.child_by_field_name("operator").is_some_and(|o| {
                        matches!(
                            &source[o.start_byte()..o.end_byte()],
                            "<" | ">" | "<=" | ">="
                        )
                    })
                });
        let has_bound_named_identifier = query::find_descendants_of_kind(condition, "identifier")
            .iter()
            .any(|id| {
                let text = &source[id.start_byte()..id.end_byte()];
                text.contains("size")
                    || text.contains("length")
                    || text.contains("count")
                    || text.contains("len")
            });
        let has_bounds_check = has_relational_comparison || has_bound_named_identifier;

        if !has_bounds_check {
            // Unbounded pointer increment detected — check if any incremented
            // pointer is a tracked buffer or is genuinely dereferenced in the body.
            for ptr_name in incremented_pointers {
                // Matches a bare `*ptr` dereference as well as the combined
                // `*ptr++`/`*ptr--` deref-and-increment idiom, where the
                // pointer_expression's argument is the update_expression
                // rather than the bare identifier.
                let derefs_ptr = query::find_descendants_of_kind(body, "pointer_expression")
                    .iter()
                    .any(|n| {
                        n.child_by_field_name("argument").is_some_and(|a| {
                            if source[a.start_byte()..a.end_byte()] == *ptr_name {
                                return true;
                            }
                            // `*ptr++` (postfix): the pointer_expression's argument is
                            // the update_expression. `*++ptr` (prefix) is NOT matched —
                            // it dereferences the pointer's *next* position, not the
                            // pre-increment one, so it isn't the same access pattern.
                            a.kind() == "update_expression"
                                && matches!(
                                    (
                                        a.child_by_field_name("operator"),
                                        a.child_by_field_name("argument")
                                    ),
                                    (Some(op), Some(arg)) if op.start_byte() > arg.start_byte()
                                )
                                && a.child_by_field_name("argument").is_some_and(|inner| {
                                    source[inner.start_byte()..inner.end_byte()] == *ptr_name
                                })
                        })
                    });
                if buffers.contains_key(&ptr_name) || derefs_ptr {
                    let start_point = while_node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Unbounded while loop with pointer increment. Loop increments '{}' without size/length bounds checking.",
                            ptr_name
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Add bounds checking to while condition (e.g., counter < max_size)".to_string()
                        ),
                        ..Default::default()
                    });
                    break; // Only report once per while loop
                }
            }
        }

        violations
    }

    /// Collect the names of local pointers in `func_node` that are tainted by an
    /// untrusted/binary accessor (see [`UNTRUSTED_BLOB_ACCESSORS`]). A pointer is
    /// tainted when it is declared/assigned directly from such a call, or aliased
    /// from an already-tainted pointer (`q = p;`). Two passes resolve simple
    /// one-hop aliasing without a full dataflow.
    fn collect_blob_tainted_pointers(&self, func_node: &Node, source: &str) -> HashSet<String> {
        let mut tainted: HashSet<String> = HashSet::new();
        // Direct taint from accessor calls.
        Self::walk_collect_blob_taint(func_node, source, &mut tainted);
        // One extra pass to propagate `q = p;` aliases (covers the common
        // "advance a cursor copy of the blob pointer" shape).
        let mut changed = true;
        let mut guard = 0;
        while changed && guard < 4 {
            changed = false;
            guard += 1;
            Self::walk_propagate_alias_taint(func_node, source, &mut tainted, &mut changed);
        }
        tainted
    }

    fn walk_collect_blob_taint(node: &Node, source: &str, tainted: &mut HashSet<String>) {
        for node in
            query::find_descendants_of_kinds(*node, &["init_declarator", "assignment_expression"])
        {
            if node.kind() == "init_declarator" {
                if let (Some(decl), Some(value)) = (
                    node.child_by_field_name("declarator"),
                    node.child_by_field_name("value"),
                ) {
                    let rhs = &source[value.start_byte()..value.end_byte()];
                    if Self::text_calls_blob_accessor(rhs) {
                        if let Some(name) = find_identifier_in_declarator(&decl, source) {
                            tainted.insert(name);
                        }
                    }
                }
            } else if node.kind() == "assignment_expression" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    if left.kind() == "identifier" {
                        let rhs = &source[right.start_byte()..right.end_byte()];
                        if Self::text_calls_blob_accessor(rhs) {
                            tainted.insert(source[left.start_byte()..left.end_byte()].to_string());
                        }
                    }
                }
            }
        }
    }

    fn walk_propagate_alias_taint(
        node: &Node,
        source: &str,
        tainted: &mut HashSet<String>,
        changed: &mut bool,
    ) {
        let propagate =
            |lhs: &str, rhs_node: &Node, tainted: &mut HashSet<String>, changed: &mut bool| {
                if rhs_node.kind() == "identifier" {
                    let rhs = &source[rhs_node.start_byte()..rhs_node.end_byte()];
                    if tainted.contains(rhs) && !tainted.contains(lhs) {
                        tainted.insert(lhs.to_string());
                        *changed = true;
                    }
                }
            };
        for node in
            query::find_descendants_of_kinds(*node, &["init_declarator", "assignment_expression"])
        {
            if node.kind() == "init_declarator" {
                if let (Some(decl), Some(value)) = (
                    node.child_by_field_name("declarator"),
                    node.child_by_field_name("value"),
                ) {
                    if let Some(name) = find_identifier_in_declarator(&decl, source) {
                        propagate(&name, &value, tainted, changed);
                    }
                }
            } else if node.kind() == "assignment_expression" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    if left.kind() == "identifier" {
                        let lhs = source[left.start_byte()..left.end_byte()].to_string();
                        propagate(&lhs, &right, tainted, changed);
                    }
                }
            }
        }
    }

    /// True if `text` contains a call to one of the untrusted blob/value accessors.
    fn text_calls_blob_accessor(text: &str) -> bool {
        UNTRUSTED_BLOB_ACCESSORS
            .iter()
            .any(|acc| text.contains(&format!("{}(", acc)))
    }

    /// `node`'s source span with every `comment`/`string_literal`/`char_literal`
    /// byte range blanked to spaces (newlines preserved, so line numbers derived
    /// from the result stay meaningful). The decode-loop heuristics below do
    /// substring/regex matching over raw source spans for expedience — this
    /// sanitization pass is what keeps a comment (`// p++ removed`) or a string
    /// literal (`"advance p < end"`) from injecting a false match into those
    /// checks, without having to re-derive each heuristic from the AST.
    fn text_sans_comments_and_strings(node: Node, source: &str) -> String {
        let base = node.start_byte();
        let mut bytes = source.as_bytes()[base..node.end_byte()].to_vec();
        for n in
            query::find_descendants_of_kinds(node, &["comment", "string_literal", "char_literal"])
        {
            let start = n.start_byte() - base;
            let end = (n.end_byte() - base).min(bytes.len());
            for b in &mut bytes[start..end] {
                if *b != b'\n' {
                    *b = b' ';
                }
            }
        }
        String::from_utf8(bytes).unwrap_or_default()
    }

    /// Detect an unbounded decode loop over an untrusted (blob/value-derived)
    /// pointer: a `while`/`for`/`do` loop that advances a tainted pointer (or
    /// feeds it to a varint reader) while chasing a terminator or continuation
    /// bit, with no dominating bound check (`p < end`, a counter `< len`, etc.).
    /// This is the ARR30-C false-negative family from the sqlite real-world audit
    /// (task 172): the rule formerly fired on bounded indices it misread and
    /// missed these genuine over-reads.
    fn check_unbounded_decode_loop(&self, loop_node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Split the loop into its control text (everything except the body — the
        // `while`/`for` condition, the `for` update clause, and a `do`-while's
        // trailing condition) and the body itself.
        let body = match Self::loop_body_node(loop_node) {
            Some(b) => b,
            None => return violations,
        };
        let loop_text = Self::text_sans_comments_and_strings(*loop_node, source);
        let body_rel_start = body.start_byte() - loop_node.start_byte();
        let body_rel_end = body.end_byte() - loop_node.start_byte();
        let header = format!(
            "{}{}",
            &loop_text[..body_rel_start],
            &loop_text[body_rel_end..]
        );
        let body_text = loop_text[body_rel_start..body_rel_end].to_string();

        // Taint is scoped to the containing function. Memoize per function so
        // the scan runs once per function rather than once per loop.
        let func_node = match find_containing_function(loop_node) {
            Some(f) => f,
            None => return violations,
        };
        let func_key = func_node.start_byte();
        if !self.decode_taint_cache.borrow().contains_key(&func_key) {
            // Cheap pre-filter: only walk the function when its text mentions a
            // blob/value accessor at all, otherwise cache an empty set.
            let func_text = Self::text_sans_comments_and_strings(func_node, source);
            let tainted = if Self::text_calls_blob_accessor(&func_text) {
                self.collect_blob_tainted_pointers(&func_node, source)
            } else {
                HashSet::new()
            };
            self.decode_taint_cache
                .borrow_mut()
                .insert(func_key, tainted);
        }
        let cache = self.decode_taint_cache.borrow();
        let tainted = match cache.get(&func_key) {
            Some(t) if !t.is_empty() => t,
            _ => return violations,
        };

        // Candidate walked pointers: tainted pointers incremented in the loop, or
        // tainted pointers passed to a varint reader inside the loop body.
        let mut candidates: Vec<String> = Vec::new();
        let scan = format!("{}\n{}", header, body_text);
        for ptr in tainted {
            let incremented = scan.contains(&format!("{}++", ptr))
                || scan.contains(&format!("++{}", ptr))
                || scan.contains(&format!("{} +=", ptr))
                || scan.contains(&format!("{}+=", ptr));
            let in_varint = VARINT_READERS.iter().any(|r| {
                // crude arg check: "READER(...ptr..." where ptr is an early arg
                if let Some(pos) = scan.find(&format!("{}(", r)) {
                    let after = &scan[pos..];
                    let argstart = after.find('(').map(|i| pos + i).unwrap_or(pos);
                    let argend = after.find(')').map(|i| pos + i).unwrap_or(scan.len());
                    if argstart < argend {
                        return scan[argstart..argend]
                            .split(|c: char| !c.is_alphanumeric() && c != '_')
                            .any(|tok| tok == ptr);
                    }
                }
                false
            });
            if incremented || in_varint {
                candidates.push(ptr.clone());
            }
        }

        for ptr in candidates {
            if Self::pointer_walk_is_bounded(&ptr, &header, &body_text) {
                continue;
            }
            let start_point = loop_node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Unbounded decode loop over untrusted pointer '{}': the loop advances a pointer derived from blob/column bytes with no bound check before the read, allowing an out-of-bounds read.",
                    ptr
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(
                    "Bound the walk against the buffer extent (e.g. `while (p < end)`/`p + n <= end`) before dereferencing or decoding.".to_string(),
                ),
                ..Default::default()
            });
        }

        violations
    }

    /// The statement node that forms a loop's body (the compound/expression
    /// statement following the header), for `while`/`for`/`do` loops.
    fn loop_body_node<'a>(loop_node: &Node<'a>) -> Option<Node<'a>> {
        if let Some(body) = loop_node.child_by_field_name("body") {
            return Some(body);
        }
        // Fallback: last statement-like child.
        let mut found = None;
        for i in 0..loop_node.child_count() {
            if let Some(child) = loop_node.child(i) {
                if matches!(
                    child.kind(),
                    "compound_statement" | "expression_statement" | "if_statement"
                ) {
                    found = Some(child);
                }
            }
        }
        found
    }

    /// True if the walk of `ptr` is bounded by a guard against an end pointer or
    /// a length counter, anywhere in the loop header or body. Conservative: any
    /// relational comparison in the header, a pointer-difference, an inequality
    /// of `ptr` itself against another expression, or a length countdown counts
    /// as "bounded" so we only fire on genuinely open-ended terminator chases.
    fn pointer_walk_is_bounded(ptr: &str, header: &str, body: &str) -> bool {
        // A relational operator in the header (e.g. `for (...; p < end; ...)`,
        // `while (n < len)`) is a bound. Note `*p != term` uses `!=`, not `<`/`>`,
        // so a pure terminator chase is not caught here.
        if header.contains('<') || header.contains('>') {
            return true;
        }
        let hay = format!("{}\n{}", header, body);
        // `ptr` itself (not `*ptr`) compared against another expression: pointer
        // bound such as `p != end`, `p == zEnd`, `p >= end`.
        for op in ["==", "!=", ">=", "<=", "<", ">"] {
            if hay.contains(&format!("{} {}", ptr, op)) || hay.contains(&format!("{}{}", ptr, op)) {
                // Exclude the dereference compare `*ptr != term`: that is the
                // terminator test, not a bound. We already keyed on the bare
                // identifier, so `*p` won't match `p ==` here.
                return true;
            }
            if hay.contains(&format!("{} {}", op, ptr)) {
                return true;
            }
        }
        // Pointer difference against another expression (`end - p`, `p - base`).
        if hay.contains(&format!("- {}", ptr))
            || hay.contains(&format!("{} -", ptr))
            || hay.contains(&format!("-{}", ptr))
        {
            return true;
        }
        false
    }

    /// Detect the param-decoder index over-read family (task 210, sqlite
    /// `kvvfsDecode` class). Target shape: a function whose input buffer is a
    /// `const char *` / `const unsigned char *` *parameter* (or a cast-alias of
    /// one) with no paired length parameter, walked inside a loop by an
    /// embedded-increment subscript (`a[++i]`, `a[i++]`) where the index is never
    /// relationally bounded against a length. Unlike the blob-accessor walk
    /// handled by [`Self::check_unbounded_decode_loop`], the bytes come straight
    /// from a parameter rather than a recognised accessor call.
    ///
    /// The plain NUL-terminated C-string walk (`while (*s) s++;`,
    /// `for (; s[i]; i++)`) is gated out two ways: its read sits in the loop
    /// *condition* (condition-guarded), and the embedded-increment subscript form
    /// is rare in that idiom.
    fn check_param_decode_overread(&self, loop_node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        let func_node = match find_containing_function(loop_node) {
            Some(f) => f,
            None => return violations,
        };
        let func_key = func_node.start_byte();
        // One finding per function: nested loops over the same buffer shouldn't
        // each emit.
        if self.param_decode_reported.borrow().contains(&func_key) {
            return violations;
        }

        if !self.param_decode_buf_cache.borrow().contains_key(&func_key) {
            let bufs = self.collect_param_decode_buffers(&func_node, source);
            self.param_decode_buf_cache
                .borrow_mut()
                .insert(func_key, bufs);
        }
        let cache = self.param_decode_buf_cache.borrow();
        let bufs = match cache.get(&func_key) {
            Some(b) if !b.is_empty() => b,
            _ => return violations,
        };

        // Split this loop into control text (condition / update) and body.
        let body = match Self::loop_body_node(loop_node) {
            Some(b) => b,
            None => return violations,
        };
        let loop_text = Self::text_sans_comments_and_strings(*loop_node, source);
        let body_rel_start = body.start_byte() - loop_node.start_byte();
        let body_rel_end = body.end_byte() - loop_node.start_byte();
        let header = format!(
            "{}{}",
            &loop_text[..body_rel_start],
            &loop_text[body_rel_end..]
        );

        let func_text = Self::text_sans_comments_and_strings(func_node, source);

        // Embedded-increment subscripts (`buf[++i]` / `buf[i++]`) on a candidate
        // buffer, attributed to the innermost enclosing loop so the same access
        // isn't double-reported by an outer loop.
        let mut hits: Vec<(String, String, tree_sitter::Point)> = Vec::new();
        Self::collect_embedded_increment_subscripts(&body, source, bufs, loop_node, &mut hits);

        for (buf, idx, point) in hits {
            // Condition-guarded read of this buffer (`while (buf[i])`) is the
            // caller-contract NUL/length walk — not an over-read.
            if header.contains(&format!("{}[", buf)) || header.contains(&format!("*{}", buf)) {
                continue;
            }
            // The index is bounded somewhere in the function (`i < n`, `n > i`).
            if Self::index_is_relationally_bounded(&idx, &func_text) {
                continue;
            }
            self.param_decode_reported.borrow_mut().insert(func_key);
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Unbounded index over-read of parameter buffer '{}': the loop advances index '{}' into a const-char* parameter (no length argument) with no bound check before the read, allowing an out-of-bounds read.",
                    buf, idx
                ),
                file_path: String::new(),
                line: point.row + 1,
                column: point.column + 1,
                suggestion: Some(
                    "Pass and check an explicit length for the input buffer (e.g. `i < nIn`) before indexing it.".to_string(),
                ),
                ..Default::default()
            });
            break;
        }

        violations
    }

    /// Collect the `const char *` / `const unsigned char *` parameters of
    /// `func_node` that have no paired length parameter (the immediately
    /// following parameter is not an integer scalar), plus any local pointer that
    /// is a cast-alias of such a parameter (`const unsigned char *aIn =
    /// (const unsigned char*)a;`).
    fn collect_param_decode_buffers(&self, func_node: &Node, source: &str) -> HashSet<String> {
        let mut bufs = HashSet::new();
        let declarator = match func_node.child_by_field_name("declarator") {
            Some(d) => d,
            None => return bufs,
        };
        let param_list = match find_param_list_node(&declarator) {
            Some(p) => p,
            None => return bufs,
        };

        // Ordered (name, is_const_char_ptr, is_int_scalar) for each parameter.
        let mut params: Vec<(Option<String>, bool, bool)> = Vec::new();
        for i in 0..param_list.child_count() {
            let param = match param_list.child(i) {
                Some(p) if p.kind() == "parameter_declaration" => p,
                _ => continue,
            };
            let text = &source[param.start_byte()..param.end_byte()];
            let is_ptr = text.contains('*');
            let is_ccp = is_ptr && text.contains("char") && text.contains("const");
            let is_int = !is_ptr && Self::type_text_is_int_scalar(text);
            let name = param
                .child_by_field_name("declarator")
                .and_then(|d| find_identifier_in_declarator(&d, source));
            params.push((name, is_ccp, is_int));
        }

        for idx in 0..params.len() {
            let (name, is_ccp, _) = &params[idx];
            if !*is_ccp {
                continue;
            }
            let name = match name {
                Some(n) => n,
                None => continue,
            };
            // Paired-length convention: a (buf, len) pair places the integer
            // length immediately after the pointer. Without that, treat the
            // buffer as length-unbounded.
            let next_is_len = params.get(idx + 1).map(|p| p.2).unwrap_or(false);
            if !next_is_len {
                bufs.insert(name.clone());
            }
        }

        if !bufs.is_empty() {
            // A couple of passes resolve `aIn = (cast)a; q = aIn;` chains.
            let mut changed = true;
            let mut guard = 0;
            while changed && guard < 3 {
                changed = false;
                guard += 1;
                Self::walk_collect_cast_aliases(func_node, source, &mut bufs, &mut changed);
            }
        }
        bufs
    }

    /// True if `text` (a non-pointer parameter declaration) names an integer
    /// scalar type — the shape of a length/count argument.
    fn type_text_is_int_scalar(text: &str) -> bool {
        const INT_TOKENS: &[&str] = &[
            "int",
            "long",
            "short",
            "size_t",
            "ssize_t",
            "unsigned",
            "int8_t",
            "int16_t",
            "int32_t",
            "int64_t",
            "uint8_t",
            "uint16_t",
            "uint32_t",
            "uint64_t",
            "intptr_t",
            "uintptr_t",
            "ptrdiff_t",
        ];
        INT_TOKENS.iter().any(|t| {
            text.split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|tok| tok == *t)
        })
    }

    /// Add to `bufs` any local pointer declared as a cast (or direct alias) of an
    /// existing candidate buffer (`const unsigned char *aIn = (cast)a;`).
    fn walk_collect_cast_aliases(
        node: &Node,
        source: &str,
        bufs: &mut HashSet<String>,
        changed: &mut bool,
    ) {
        for node in query::find_descendants_of_kind(*node, "init_declarator") {
            if let (Some(decl), Some(value)) = (
                node.child_by_field_name("declarator"),
                node.child_by_field_name("value"),
            ) {
                if let Some(inner) = Self::unwrap_to_identifier(&value, source) {
                    if bufs.contains(&inner) {
                        if let Some(name) = find_identifier_in_declarator(&decl, source) {
                            if !bufs.contains(&name) {
                                bufs.insert(name);
                                *changed = true;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Unwrap casts / parentheses to the bare identifier they wrap, if any.
    fn unwrap_to_identifier(node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => Some(source[node.start_byte()..node.end_byte()].to_string()),
            "cast_expression" => node
                .child_by_field_name("value")
                .and_then(|v| Self::unwrap_to_identifier(&v, source)),
            "parenthesized_expression" => {
                // The wrapped expression is the non-punctuation child.
                let mut found = None;
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.is_named() {
                            found = Self::unwrap_to_identifier(&child, source);
                        }
                    }
                }
                found
            }
            _ => None,
        }
    }

    /// Walk `body`, collecting `(buffer, index_var, position)` for every
    /// `buf[++i]` / `buf[i++]` subscript whose `buf` is a candidate and whose
    /// innermost enclosing loop is `loop_node` (so an outer loop won't also claim
    /// it).
    fn collect_embedded_increment_subscripts(
        node: &Node,
        source: &str,
        bufs: &HashSet<String>,
        loop_node: &Node,
        out: &mut Vec<(String, String, tree_sitter::Point)>,
    ) {
        for node in query::find_descendants_of_kind(*node, "subscript_expression") {
            if let (Some(arg), Some(index)) = (
                node.child_by_field_name("argument"),
                node.child_by_field_name("index"),
            ) {
                if arg.kind() == "identifier" {
                    let buf = source[arg.start_byte()..arg.end_byte()].to_string();
                    if bufs.contains(&buf) && index.kind() == "update_expression" {
                        if let Some(operand) = index.child_by_field_name("argument") {
                            if operand.kind() == "identifier"
                                && Self::innermost_loop_of(&node)
                                    .map(|l| l.start_byte() == loop_node.start_byte())
                                    .unwrap_or(false)
                            {
                                let idx =
                                    source[operand.start_byte()..operand.end_byte()].to_string();
                                out.push((buf, idx, node.start_position()));
                            }
                        }
                    }
                }
            }
        }
    }

    /// The nearest enclosing `while`/`for`/`do` loop of `node`, if any.
    fn innermost_loop_of<'a>(node: &Node<'a>) -> Option<Node<'a>> {
        let mut cur = node.parent();
        while let Some(n) = cur {
            if matches!(
                n.kind(),
                "while_statement" | "for_statement" | "do_statement"
            ) {
                return Some(n);
            }
            cur = n.parent();
        }
        None
    }

    /// True if `idx` appears as a whole token next to a relational operator
    /// (`idx < n`, `n >= idx`) anywhere in `func_text` — i.e. the index is
    /// bounded against a length somewhere in the function.
    fn index_is_relationally_bounded(idx: &str, func_text: &str) -> bool {
        let e = regex::escape(idx);
        let pat = format!(r"(\b{0}\b\s*(<=?|>=?))|((<=?|>=?)\s*\b{0}\b)", e);
        regex::Regex::new(&pat)
            .map(|re| re.is_match(func_text))
            .unwrap_or(false)
    }

    /// Build the per-file interprocedural over-read summary (task 211): walk every
    /// `function_definition` in the translation unit and record, by function name,
    /// the positional indices of its `const char *` parameters that are walked
    /// unbounded. Only functions with at least one such parameter are stored.
    fn build_helper_overread_summary(
        &self,
        root: &Node,
        source: &str,
    ) -> HashMap<String, Vec<usize>> {
        let mut summary = HashMap::new();
        self.collect_overread_helpers(root, source, &mut summary);
        summary
    }

    fn collect_overread_helpers(
        &self,
        node: &Node,
        source: &str,
        out: &mut HashMap<String, Vec<usize>>,
    ) {
        if node.kind() == "function_definition" {
            if let Some(name) = self.get_function_name(node, source) {
                let indices = Self::helper_overread_param_indices(node, source);
                if !indices.is_empty() {
                    out.insert(name, indices);
                }
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_overread_helpers(&child, source, out);
            }
        }
    }

    /// Positional indices of `const char *` parameters of `func_node` that are
    /// walked unbounded: indexed by an embedded-increment subscript (`p[i++]` /
    /// `p[++i]`) inside a loop whose index is never relationally bounded in the
    /// function body. Mirrors `check_param_decode_overread`'s over-read shape but
    /// (a) reports the *parameter position* for call-site mapping and (b) drops the
    /// condition-guard veto — the call-site taint gate in
    /// `check_overread_helper_callsite` supplies the precision instead.
    fn helper_overread_param_indices(func_node: &Node, source: &str) -> Vec<usize> {
        let candidates = Self::const_char_ptr_params_without_length(func_node, source);
        if candidates.is_empty() {
            return Vec::new();
        }
        let func_text = &source[func_node.start_byte()..func_node.end_byte()];
        let cand_names: HashSet<String> = candidates.iter().map(|(n, _)| n.clone()).collect();
        let mut overread: HashSet<String> = HashSet::new();
        Self::walk_param_overread(func_node, source, &cand_names, func_text, &mut overread);
        let mut out: Vec<usize> = candidates
            .iter()
            .filter(|(n, _)| overread.contains(n))
            .map(|(_, idx)| *idx)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Ordered `(name, position)` for each `const char *` parameter of `func_node`
    /// that has no paired length parameter (the next parameter is not an integer
    /// scalar). Position counts only `parameter_declaration` children, matching the
    /// positional index of named call-site arguments.
    fn const_char_ptr_params_without_length(
        func_node: &Node,
        source: &str,
    ) -> Vec<(String, usize)> {
        let declarator = match func_node.child_by_field_name("declarator") {
            Some(d) => d,
            None => return Vec::new(),
        };
        let param_list = match find_param_list_node(&declarator) {
            Some(p) => p,
            None => return Vec::new(),
        };
        // (name, is_const_char_ptr, is_int_scalar) per parameter, in order.
        let mut params: Vec<(Option<String>, bool, bool)> = Vec::new();
        for i in 0..param_list.child_count() {
            let param = match param_list.child(i) {
                Some(p) if p.kind() == "parameter_declaration" => p,
                _ => continue,
            };
            let text = &source[param.start_byte()..param.end_byte()];
            let is_ptr = text.contains('*');
            let is_ccp = is_ptr && text.contains("char") && text.contains("const");
            let is_int = !is_ptr && Self::type_text_is_int_scalar(text);
            let name = param
                .child_by_field_name("declarator")
                .and_then(|d| find_identifier_in_declarator(&d, source));
            params.push((name, is_ccp, is_int));
        }
        let mut out = Vec::new();
        for idx in 0..params.len() {
            let (name, is_ccp, _) = &params[idx];
            if !*is_ccp {
                continue;
            }
            if let Some(name) = name {
                let next_is_len = params.get(idx + 1).map(|p| p.2).unwrap_or(false);
                if !next_is_len {
                    out.push((name.clone(), idx));
                }
            }
        }
        out
    }

    /// Insert into `overread` any candidate buffer name indexed by an
    /// embedded-increment subscript (`buf[i++]` / `buf[++i]`) inside a loop whose
    /// index is never relationally bounded in `func_text`.
    fn walk_param_overread(
        node: &Node,
        source: &str,
        cand_names: &HashSet<String>,
        func_text: &str,
        overread: &mut HashSet<String>,
    ) {
        for node in query::find_descendants_of_kind(*node, "subscript_expression") {
            if let (Some(arg), Some(index)) = (
                node.child_by_field_name("argument"),
                node.child_by_field_name("index"),
            ) {
                if arg.kind() == "identifier" {
                    let buf = source[arg.start_byte()..arg.end_byte()].to_string();
                    if cand_names.contains(&buf)
                        && index.kind() == "update_expression"
                        && Self::innermost_loop_of(&node).is_some()
                    {
                        if let Some(operand) = index.child_by_field_name("argument") {
                            if operand.kind() == "identifier" {
                                let idx =
                                    source[operand.start_byte()..operand.end_byte()].to_string();
                                if !Self::index_is_relationally_bounded(&idx, func_text) {
                                    overread.insert(buf);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// The base pointer identifier of a call argument, stripping `+ offset`
    /// arithmetic, casts, and parentheses (`zOut + p->nPrefix` -> `zOut`,
    /// `(const unsigned char*)a` -> `a`).
    fn arg_base_identifier(node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => Some(source[node.start_byte()..node.end_byte()].to_string()),
            "cast_expression" => node
                .child_by_field_name("value")
                .and_then(|v| Self::arg_base_identifier(&v, source)),
            "parenthesized_expression" => {
                let mut found = None;
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.is_named() {
                            found = Self::arg_base_identifier(&child, source);
                        }
                    }
                }
                found
            }
            "binary_expression" => node
                .child_by_field_name("left")
                .and_then(|l| Self::arg_base_identifier(&l, source))
                .or_else(|| {
                    node.child_by_field_name("right")
                        .and_then(|r| Self::arg_base_identifier(&r, source))
                }),
            "pointer_expression" | "unary_expression" => node
                .child_by_field_name("argument")
                .and_then(|a| Self::arg_base_identifier(&a, source)),
            _ => None,
        }
    }

    /// Interprocedural over-read at a call site (task 211). When the callee is a
    /// helper that walks one of its `const char *` parameters unbounded (per the
    /// per-file `helper_overread_summary`) and the corresponding argument resolves
    /// — after stripping `+ offset` / casts — to a pointer tainted by a
    /// blob/value accessor in the *caller*, the call passes untrusted bytes into an
    /// unbounded read with no length argument. Canonical: nextchar.c
    /// `readUtf8(zOut + p->nPrefix, &cNext)` where `zOut = sqlite3_column_text(...)`.
    fn check_overread_helper_callsite(&self, call_node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Callee must be a bare-identifier function with a known over-read summary.
        let callee = match call_node.child_by_field_name("function") {
            Some(f) if f.kind() == "identifier" => source[f.start_byte()..f.end_byte()].to_string(),
            _ => return violations,
        };
        let indices = match self
            .helper_overread_summary
            .borrow()
            .as_ref()
            .and_then(|s| s.get(&callee))
        {
            Some(v) if !v.is_empty() => v.clone(),
            _ => return violations,
        };

        // Positional (named) arguments at the call site.
        let arg_list = match call_node.child_by_field_name("arguments") {
            Some(a) => a,
            None => return violations,
        };
        let mut args: Vec<Node> = Vec::new();
        for i in 0..arg_list.child_count() {
            if let Some(child) = arg_list.child(i) {
                if child.is_named() {
                    args.push(child);
                }
            }
        }

        // Caller-scope blob/value taint, memoized in the shared decode cache.
        let caller = match find_containing_function(call_node) {
            Some(f) => f,
            None => return violations,
        };
        let caller_key = caller.start_byte();
        if !self.decode_taint_cache.borrow().contains_key(&caller_key) {
            let func_text = &source[caller.start_byte()..caller.end_byte()];
            let tainted = if Self::text_calls_blob_accessor(func_text) {
                self.collect_blob_tainted_pointers(&caller, source)
            } else {
                HashSet::new()
            };
            self.decode_taint_cache
                .borrow_mut()
                .insert(caller_key, tainted);
        }
        let cache = self.decode_taint_cache.borrow();
        let tainted = match cache.get(&caller_key) {
            Some(t) if !t.is_empty() => t,
            _ => return violations,
        };

        for k in indices {
            let arg = match args.get(k) {
                Some(a) => a,
                None => continue,
            };
            let base = match Self::arg_base_identifier(arg, source) {
                Some(b) => b,
                None => continue,
            };
            if !tainted.contains(&base) {
                continue;
            }
            let point = call_node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Out-of-bounds read passing untrusted pointer '{}' to '{}': the callee walks this argument unbounded (no length argument), so bytes derived from a blob/column accessor are read past their extent.",
                    base, callee
                ),
                file_path: String::new(),
                line: point.row + 1,
                column: point.column + 1,
                suggestion: Some(
                    "Pass and enforce an explicit length/end for the buffer, or bound the helper's walk against the input extent.".to_string(),
                ),
                ..Default::default()
            });
            break;
        }

        violations
    }

    /// Check for malloc/calloc/realloc calls without proper NULL checks before pointer arithmetic
    /// Detects patterns where malloc() result is used in pointer arithmetic without NULL validation
    fn check_malloc_null_pointer_arithmetic(
        &self,
        func_node: &Node,
        source: &str,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Track all malloc/calloc/realloc assignments and their variable names
        let mut malloc_vars: HashMap<String, usize> = HashMap::new(); // var_name -> line_number

        // First pass: find all malloc/calloc/realloc calls
        self.find_malloc_assignments(func_node, source, &mut malloc_vars);

        if malloc_vars.is_empty() {
            return violations; // No malloc calls, nothing to check
        }

        // Second pass: for each malloc variable, check if it has NULL check with return/exit
        for var_name in malloc_vars.keys() {
            let has_safe_null_check =
                self.has_safe_null_check_in_function(func_node, source, var_name);

            if !has_safe_null_check {
                // Third pass: find pointer arithmetic on this variable
                if let Some(violation_line) =
                    self.find_pointer_arithmetic_usage(func_node, source, var_name)
                {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Pointer arithmetic on potentially NULL pointer '{}' from a heap allocator. \
                            No NULL check found before use at line {}.",
                            var_name, violation_line
                        ),
                        file_path: String::new(),
                        line: violation_line,
                        column: 1,
                        suggestion: Some(format!(
                            "Add NULL check: if ({} == NULL) {{ /* handle error */ }}",
                            var_name
                        )),
                        ..Default::default()
                    });
                }
            }
        }

        violations
    }

    /// Whether `value` is a call to a heap allocator (malloc/calloc/
    /// realloc/aligned_alloc/strdup/strndup), unwrapping a leading cast
    /// (`(char *)malloc(n)`) if present. Matched against the callee
    /// identifier node, not the RHS's raw text, so a string-literal
    /// initializer like `char *msg = "malloc(10) failed";` can't be
    /// mistaken for an allocation.
    ///
    /// Only feeds `check_malloc_null_pointer_arithmetic`'s NULL-check-
    /// before-pointer-arithmetic tracking here, not any numeric-size
    /// extraction — so widening from the original malloc/calloc/realloc-only
    /// list to the shared `call_roles::is_allocator_call` set (task 498)
    /// is a plain recall improvement: `aligned_alloc`/`strdup`/`strndup`
    /// can also return NULL and are equally subject to the same
    /// missing-NULL-check bug.
    fn is_alloc_call(value: &Node, source: &str) -> bool {
        let value = match value.kind() {
            "cast_expression" => value.child_by_field_name("value").unwrap_or(*value),
            _ => *value,
        };
        value.kind() == "call_expression"
            && value.child_by_field_name("function").is_some_and(|f| {
                call_roles::is_allocator_call(&source[f.start_byte()..f.end_byte()])
            })
    }

    /// Find all malloc/calloc/realloc assignments in a function
    fn find_malloc_assignments(
        &self,
        node: &Node,
        source: &str,
        malloc_vars: &mut HashMap<String, usize>,
    ) {
        // Check current node for malloc assignment
        if node.kind() == "declaration" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "init_declarator" {
                        if child
                            .child_by_field_name("value")
                            .is_some_and(|v| Self::is_alloc_call(&v, source))
                        {
                            if let Some(var_name) = self.extract_assignment_lhs(node, source) {
                                let line = node.start_position().row + 1;
                                malloc_vars.insert(var_name, line);
                            }
                        }
                        break;
                    }
                }
            }
        } else if node.kind() == "assignment_expression" {
            if node
                .child_by_field_name("right")
                .is_some_and(|r| Self::is_alloc_call(&r, source))
            {
                if let Some(var_name) = self.extract_assignment_lhs(node, source) {
                    let line = node.start_position().row + 1;
                    malloc_vars.insert(var_name, line);
                }
            }
        }

        // Recursively check children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.find_malloc_assignments(&child, source, malloc_vars);
            }
        }
    }

    /// Extract the left-hand side variable name from an assignment
    fn extract_assignment_lhs(&self, node: &Node, source: &str) -> Option<String> {
        // For declaration: char *buffer = malloc(...)
        if node.kind() == "declaration" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "init_declarator" {
                        // Get the declarator (left side)
                        if let Some(declarator) = child.child(0) {
                            let name = get_identifier_from_declarator(&declarator, source);
                            return if name.is_empty() { None } else { Some(name) };
                        }
                    }
                }
            }
        }

        // For assignment_expression: buffer = malloc(...)
        if node.kind() == "assignment_expression" {
            if let Some(lhs) = node.child(0) {
                if lhs.kind() == "identifier" {
                    return Some(source[lhs.start_byte()..lhs.end_byte()].to_string());
                }
            }
        }

        None
    }

    /// Check if there's a safe NULL check (with return/exit) for the given variable in the function
    fn has_safe_null_check_in_function(
        &self,
        func_node: &Node,
        source: &str,
        var_name: &str,
    ) -> bool {
        self.find_safe_null_check(func_node, source, var_name)
    }

    /// Recursively search for NULL check
    /// A NULL check is considered safe if it exists, even without explicit return/exit
    /// The presence of the check indicates awareness of the NULL possibility
    fn find_safe_null_check(&self, node: &Node, source: &str, var_name: &str) -> bool {
        // Check if this is an if statement with NULL check
        if node.kind() == "if_statement" {
            if let Some(condition) = node.child_by_field_name("condition") {
                if Self::condition_has_null_check(&condition, source, var_name) {
                    return true; // NULL check found - considered safe
                }
            }
        }

        // Recursively check children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if self.find_safe_null_check(&child, source, var_name) {
                    return true;
                }
            }
        }

        false
    }

    /// Whether `condition` checks `var_name` for NULL: `var == NULL`,
    /// `NULL == var`, `var != NULL`, `NULL != var`, or `!var`. Matched
    /// against the comparison's own operand nodes, not the condition's raw
    /// text, so a comment or string literal mentioning the variable name
    /// can't fake a check that isn't actually there.
    fn condition_has_null_check(condition: &Node, source: &str, var_name: &str) -> bool {
        let is_var = |n: &Node| {
            n.kind() == "identifier" && &source[n.start_byte()..n.end_byte()] == var_name
        };
        // `NULL` is its own dedicated node kind ("null") in tree-sitter-c,
        // not an `identifier` — plus a defensive fallback for a
        // project-defined `NULL` macro that resolves to a plain identifier.
        let is_null = |n: &Node| {
            n.kind() == "null"
                || (n.kind() == "identifier" && &source[n.start_byte()..n.end_byte()] == "NULL")
        };

        let has_binary_null_check =
            query::find_descendants_of_kind(*condition, "binary_expression")
                .iter()
                .any(|cmp| {
                    let is_eq_or_neq = cmp.child_by_field_name("operator").is_some_and(|o| {
                        matches!(&source[o.start_byte()..o.end_byte()], "==" | "!=")
                    });
                    let (Some(left), Some(right)) = (
                        cmp.child_by_field_name("left"),
                        cmp.child_by_field_name("right"),
                    ) else {
                        return false;
                    };
                    is_eq_or_neq
                        && ((is_var(&left) && is_null(&right))
                            || (is_null(&left) && is_var(&right)))
                });
        if has_binary_null_check {
            return true;
        }

        query::find_descendants_of_kind(*condition, "unary_expression")
            .iter()
            .any(|u| {
                u.child_by_field_name("operator")
                    .is_some_and(|o| &source[o.start_byte()..o.end_byte()] == "!")
                    && u.child_by_field_name("argument")
                        .is_some_and(|a| is_var(&a))
            })
    }

    /// Find pointer arithmetic usage of the given variable
    /// Returns the line number where pointer arithmetic is used, or None
    fn find_pointer_arithmetic_usage(
        &self,
        node: &Node,
        source: &str,
        var_name: &str,
    ) -> Option<usize> {
        let is_var = |n: &Node| {
            n.kind() == "identifier" && &source[n.start_byte()..n.end_byte()] == var_name
        };

        // `var + offset` / `offset + var` — matched against the binary `+`
        // operator's own operand nodes, not the enclosing span's raw text,
        // so this can't collide with an unrelated `== NULL`/`!= NULL` check
        // elsewhere in the same (possibly large) enclosing node.
        if node.kind() == "binary_expression" {
            let is_plus = node
                .child_by_field_name("operator")
                .is_some_and(|o| &source[o.start_byte()..o.end_byte()] == "+");
            if is_plus {
                let involves_var = [
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ]
                .into_iter()
                .flatten()
                .any(|side| is_var(&side));
                if involves_var {
                    return Some(node.start_position().row + 1);
                }
            }
        }

        // `var += offset`
        if node.kind() == "assignment_expression" {
            let is_plus_eq = node
                .child_by_field_name("operator")
                .is_some_and(|o| &source[o.start_byte()..o.end_byte()] == "+=");
            if is_plus_eq && node.child_by_field_name("left").is_some_and(|l| is_var(&l)) {
                return Some(node.start_position().row + 1);
            }
        }

        // Recursively check children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(line) = self.find_pointer_arithmetic_usage(&child, source, var_name) {
                    return Some(line);
                }
            }
        }

        None
    }

    /// Find all structs with flexible array members
    /// Returns HashMap of struct_name -> flexible_member_name
    fn find_flexible_array_structs(&self, root: &Node, source: &str) -> HashMap<String, String> {
        let mut flexible_structs = HashMap::new();
        self.collect_flexible_array_structs(root, source, &mut flexible_structs);
        flexible_structs
    }

    /// Of `flexible_array_structs` (struct name -> its trailing flexible/
    /// struct-hack member name), return the member names whose owning
    /// struct is allocated somewhere in the file with a
    /// `sizeof(struct X) + N * sizeof(elem)`-style expression that reserves
    /// *extra* space beyond the struct itself -- proof that the member's
    /// real element count lives at the allocation site, not its declared
    /// size (task 554). Both a direct literal-arithmetic size expression
    /// and one hidden behind a file-local function-like macro (e.g. a
    /// `SZ(n)` wrapper) are recognized: the macro case is resolved via
    /// `macro_expand::expand_invocation` before pattern-matching, since
    /// `buffer_size`'s parsers only ever see literal text.
    fn find_variable_sized_flexible_members(
        &self,
        source: &str,
        flexible_array_structs: &HashMap<String, String>,
        function_macros: &HashMap<String, FunctionMacro>,
    ) -> HashSet<String> {
        let mut result = HashSet::new();
        for (struct_name, member_name) in flexible_array_structs {
            if Self::struct_has_variable_sized_alloc(source, struct_name, member_name)
                || function_macros.values().any(|m| {
                    Self::text_reserves_extra_space_for_struct(&m.body, struct_name, member_name)
                })
            {
                result.insert(member_name.clone());
            }
        }
        result
    }

    /// Does the file's source text (or, via the `function_macros` check in
    /// `find_variable_sized_flexible_members`, a macro body) reserve extra
    /// space for `struct_name`'s trailing flexible/struct-hack member
    /// `member_name`, via either the `sizeof(struct struct_name) +
    /// N*sizeof(elem)` idiom or the `offsetof(struct_name, member_name) +
    /// N*sizeof(elem)` idiom (the latter is how real-world code -- e.g.
    /// sqlite's FTS3/FTS5 code, task 537's corpus -- actually computes this
    /// size, since it doesn't depend on the compiler's struct padding)?
    ///
    /// Deliberately a whole-file text scan rather than tracing the
    /// allocation call's argument expression: the size computation is
    /// commonly one indirection removed from the call itself (stored in a
    /// local `nByte = sizeof(struct X) + n*sizeof(elem)` and only the local
    /// passed to the allocator), or hidden entirely inside a `SZ(N)`-style
    /// macro's *body* (checked separately against `function_macros`, since
    /// the macro is usually defined once per struct and reused generically
    /// without repeating the struct name at each call site). A pattern this
    /// distinctive (`sizeof`/`offsetof` naming this exact struct, plus
    /// extra arithmetic) essentially only ever appears in the
    /// struct-hack-allocation context, so a plain text match is a safe,
    /// low-risk proxy for "is this struct actually allocated this way
    /// somewhere" without needing to prove the call site itself.
    fn struct_has_variable_sized_alloc(source: &str, struct_name: &str, member_name: &str) -> bool {
        Self::text_reserves_extra_space_for_struct(source, struct_name, member_name)
    }

    /// Does `text` contain `sizeof(struct_name)`/`sizeof(struct
    /// struct_name)`, or `offsetof(struct_name, member_name)`, *plus*
    /// additional arithmetic -- i.e. more than just the bare struct size or
    /// bare offset, proving extra space was reserved for a trailing
    /// flexible/struct-hack member? `offsetof` is the more common
    /// real-world idiom (it doesn't depend on the compiler's struct
    /// padding); `sizeof` is the simpler/older one.
    fn text_reserves_extra_space_for_struct(
        text: &str,
        struct_name: &str,
        member_name: &str,
    ) -> bool {
        let sizeof_pattern = format!(
            r"sizeof\s*\(\s*(struct\s+)?{}\s*\)",
            regex::escape(struct_name)
        );
        let offsetof_pattern = format!(
            r"offsetof\s*\(\s*{}\s*,\s*{}\s*\)",
            regex::escape(struct_name),
            regex::escape(member_name)
        );
        for pattern in [&sizeof_pattern, &offsetof_pattern] {
            let Ok(re) = regex::Regex::new(pattern) else {
                continue;
            };
            for m in re.find_iter(text) {
                // The bare match alone (modulo surrounding whitespace/
                // parens on its own line/statement) just accounts for the
                // struct itself -- no extra space. `+`/`*` immediately
                // adjacent (outside the match) is the "+ N * sizeof(elem)"
                // extra term that proves this is a struct-hack allocation.
                let after = text[m.end()..].trim_start();
                let before = text[..m.start()].trim_end();
                let adjacent_op = |s: &str, front: bool| {
                    let c = if front {
                        s.chars().next()
                    } else {
                        s.chars().next_back()
                    };
                    matches!(c, Some('+') | Some('*'))
                };
                if adjacent_op(after, true) || adjacent_op(before, false) {
                    return true;
                }
            }
        }
        false
    }

    /// Recursively collect structs with flexible array members
    fn collect_flexible_array_structs(
        &self,
        node: &Node,
        source: &str,
        flexible_structs: &mut HashMap<String, String>,
    ) {
        // Look for struct_specifier nodes
        if node.kind() == "struct_specifier" {
            // Try to extract struct name and check for flexible array member
            if let Some(name_node) = node.child_by_field_name("name") {
                let struct_name = &source[name_node.start_byte()..name_node.end_byte()];

                // Check if struct has a field_declaration_list
                if let Some(body_node) = node.child_by_field_name("body") {
                    // Look for last field - if it's an array with no size, it's flexible
                    if let Some(flexible_member) =
                        self.find_flexible_array_member(&body_node, source)
                    {
                        flexible_structs.insert(struct_name.to_string(), flexible_member);
                    }
                }
            }
        }

        // Recursively check children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_flexible_array_structs(&child, source, flexible_structs);
            }
        }
    }

    /// Find flexible array member in a struct body (field_declaration_list)
    /// Returns the member name if found
    fn find_flexible_array_member(&self, body_node: &Node, source: &str) -> Option<String> {
        // Get the last field_declaration
        let mut last_field = None;
        for i in 0..body_node.child_count() {
            if let Some(child) = body_node.child(i) {
                if child.kind() == "field_declaration" {
                    last_field = Some(child);
                }
            }
        }

        // Check if last field is a flexible array (array with no size)
        if let Some(field) = last_field {
            let field_text = &source[field.start_byte()..field.end_byte()];

            // Flexible array pattern: identifier[] with no size (C99);
            // identifier[1] (the pre-C99 "struct hack" idiom -- a literal
            // size of exactly 1 as the trailing field); or identifier[NAME]
            // where NAME's own spelling names it as a flexible-array-size
            // macro (e.g. sqlite's `FLEXARRAY`, which expands to nothing
            // under C99 or `1` otherwise -- sqc has no preprocessor, so the
            // bracket contents are seen as a bare, unresolved identifier
            // either way). All three are the same "real size lives at the
            // allocation site, not the declaration" pattern (task 554).
            if let Some(open_pos) = field_text.rfind('[') {
                if let Some(close_rel) = field_text[open_pos..].find(']') {
                    let inside = field_text[open_pos + 1..open_pos + close_rel].trim();
                    let is_flexible_size = inside.is_empty()
                        || inside == "1"
                        || (inside
                            .chars()
                            .next()
                            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                            && inside
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                            && inside.to_ascii_uppercase().contains("FLEX"));
                    if is_flexible_size {
                        let before_bracket = &field_text[..open_pos];
                        if let Some(identifier) = before_bracket.split_whitespace().last() {
                            return Some(identifier.trim_end_matches('[').to_string());
                        }
                    }
                }
            }
        }

        None
    }

    /// Find identifier in a node
    #[allow(dead_code)]
    fn find_identifier_in_node(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(source[node.start_byte()..node.end_byte()].to_string());
        }

        // Recursively check children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(id) = self.find_identifier_in_node(&child, source) {
                    return Some(id);
                }
            }
        }

        None
    }

    /// Check for insufficient malloc of flexible array structs
    /// Detects pointer arithmetic on flexible array members
    fn check_flexible_array_malloc(
        &self,
        func_node: &Node,
        source: &str,
        flexible_array_structs: &HashMap<String, String>,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        if flexible_array_structs.is_empty() {
            return violations; // No flexible array structs
        }

        // Find ALL pointer arithmetic on flexible array members
        // (This is suspicious because it requires proper allocation)
        for (struct_name, member_name) in flexible_array_structs {
            if let Some(violation_line) =
                self.find_any_flexible_member_arithmetic(func_node, source, member_name)
            {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Pointer arithmetic on flexible array member '{}'. \
                        Ensure struct '{}' is allocated with extra space: malloc(sizeof(struct {}) + n * sizeof(...))",
                        member_name, struct_name, struct_name
                    ),
                    file_path: String::new(),
                    line: violation_line,
                    column: 1,
                    suggestion: Some(format!(
                        "Verify allocation includes space for flexible array: malloc(sizeof(struct {}) + array_size * sizeof(element))",
                        struct_name
                    )),
                    ..Default::default()
                });
            }
        }

        violations
    }

    /// Find while loops with increment in condition - unsafe pattern with flexible arrays
    /// Pattern: while (ptr++ != ...) or while (ptr-- != ...)
    fn find_any_flexible_member_arithmetic(
        &self,
        node: &Node,
        source: &str,
        _member_name: &str,
    ) -> Option<usize> {
        // Look for while loops with increment/decrement in the condition
        if node.kind() == "while_statement" {
            // Get the condition part of the while loop
            if let Some(condition_node) = node.child_by_field_name("condition") {
                let condition_text =
                    &source[condition_node.start_byte()..condition_node.end_byte()];

                // Check if the condition contains increment or decrement operators
                // This is the unsafe pattern when combined with flexible array members
                if condition_text.contains("++") || condition_text.contains("--") {
                    return Some(node.start_position().row + 1);
                }
            }
        }

        // Recursively check children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(line) =
                    self.find_any_flexible_member_arithmetic(&child, source, _member_name)
                {
                    return Some(line);
                }
            }
        }

        None
    }

    /// Find the function_declarator node within a function_definition
    /// Handles both direct children and nested cases (e.g., pointer return types)
    fn find_function_declarator<'a>(&self, func_def_node: &'a Node) -> Option<Node<'a>> {
        for i in 0..func_def_node.child_count() {
            if let Some(child) = func_def_node.child(i) {
                if child.kind() == "function_declarator" {
                    return Some(child);
                } else if child.kind() == "pointer_declarator" {
                    // For pointer return types like int *f(...), the function_declarator is nested
                    for j in 0..child.child_count() {
                        if let Some(nested) = child.child(j) {
                            if nested.kind() == "function_declarator" {
                                return Some(nested);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Extract operands from binary expression (e.g., "buffer + offset")
    /// Returns (left_operand, right_operand) if both are identifiers
    fn extract_binary_expr_operands(&self, node: &Node, source: &str) -> Option<(String, String)> {
        // Look for pattern: identifier + identifier
        let mut left_name = None;
        let mut right_name = None;
        let mut found_plus = false;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" if left_name.is_none() => {
                        left_name = Some(source[child.start_byte()..child.end_byte()].to_string());
                    }
                    "+" => {
                        found_plus = true;
                    }
                    "identifier" if found_plus && right_name.is_none() => {
                        right_name = Some(source[child.start_byte()..child.end_byte()].to_string());
                    }
                    _ => {}
                }
            }
        }

        if let (Some(left), Some(right)) = (left_name, right_name) {
            Some((left, right))
        } else {
            None
        }
    }

    /// Check if a function parameter has a lower bound check (>= 0 or > -1)
    fn has_lower_bound_check(&self, func_node: &Node, param_name: &str, source: &str) -> bool {
        let func_text = &source[func_node.start_byte()..func_node.end_byte()];

        // Look for patterns like: if (param >= 0) or if (param > -1) or if (0 <= param)
        let lower_bound_patterns = [
            format!(r"{}\s*>=\s*0", regex::escape(param_name)),
            format!(r"{}\s*>\s*-1", regex::escape(param_name)),
            format!(r"0\s*<=\s*{}", regex::escape(param_name)),
        ];

        for pattern in &lower_bound_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(func_text) {
                    return true;
                }
            }
        }

        false
    }

    /// Extract pointer arithmetic information from assignment
    fn extract_pointer_arithmetic(
        &self,
        node: &Node,
        source: &str,
    ) -> Option<(String, OffsetValue)> {
        let text = &source[node.start_byte()..node.end_byte()];

        // Pattern: ptr += offset
        if text.contains("+=") {
            let parts: Vec<&str> = text.split("+=").collect();
            if parts.len() == 2 {
                let ptr_name = parts[0].trim().to_string();
                let offset_str = parts[1].trim().trim_end_matches(';');

                let offset = if let Ok(const_val) = offset_str.parse::<usize>() {
                    OffsetValue::Constant(const_val)
                } else {
                    OffsetValue::Variable(offset_str.to_string())
                };

                return Some((ptr_name, offset));
            }
        }

        // Pattern: ptr = ptr + offset
        if text.contains('=') && text.contains('+') {
            let parts: Vec<&str> = text.split('=').collect();
            if parts.len() == 2 {
                let ptr_name = parts[0].trim().to_string();
                let rhs = parts[1].trim();

                if rhs.starts_with(&ptr_name) && rhs.contains('+') {
                    let offset_parts: Vec<&str> = rhs.split('+').collect();
                    if offset_parts.len() == 2 {
                        let offset_str = offset_parts[1].trim().trim_end_matches(';');

                        let offset = if let Ok(const_val) = offset_str.parse::<usize>() {
                            OffsetValue::Constant(const_val)
                        } else {
                            OffsetValue::Variable(offset_str.to_string())
                        };

                        return Some((ptr_name, offset));
                    }
                }
            }
        }

        None
    }

    /// Check if assignment is pointer arithmetic
    fn is_pointer_arithmetic_assignment(&self, node: &Node, source: &str) -> bool {
        let text = &source[node.start_byte()..node.end_byte()];
        text.contains("+=") || (text.contains('=') && text.contains('+'))
    }
}

impl Arr30C {
    /// Internal recursive check function that carries buffer_info through the tree
    fn check_with_buffer_info(
        &self,
        node: &Node,
        source: &str,
        buffer_info: &HashMap<String, BufferInfo>,
        aliases: &HashMap<String, PointerAlias>,
        function_macros: &HashMap<String, FunctionMacro>,
        flexible_array_structs: &HashMap<String, String>, // struct_name -> flexible_member_name
        macro_constants: &HashMap<String, i64>, // macro_name -> value (for loop bound resolution)
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Clone the maps to allow modification during traversal
        let mut local_buffers = buffer_info.clone();
        let mut local_aliases = aliases.clone();

        // Check multiple violation patterns BEFORE extracting declarations
        // This ensures we use the parent's context for checking this node
        match node.kind() {
            "subscript_expression" => {
                violations.extend(self.check_array_subscript(
                    node,
                    source,
                    &local_buffers,
                    &local_aliases,
                    macro_constants,
                ));
            }
            "assignment_expression" if self.is_pointer_arithmetic_assignment(node, source) => {
                violations.extend(self.check_pointer_arithmetic(
                    node,
                    source,
                    &local_buffers,
                    &local_aliases,
                ));
            }
            "call_expression" => {
                violations.extend(self.check_dangerous_function_call(node, source, &local_buffers));
                violations.extend(self.check_macro_invocation(
                    node,
                    source,
                    &local_buffers,
                    function_macros,
                ));
                // Interprocedural over-read: a tainted (blob/value-derived)
                // pointer passed into a helper that walks the matching param
                // unbounded, with no length argument (task 211).
                violations.extend(self.check_overread_helper_callsite(node, source));
            }
            "return_statement" => {
                // Check for pointer arithmetic in return statements like: return buffer + offset
                violations.extend(self.check_return_pointer_arithmetic(
                    node,
                    source,
                    &local_buffers,
                    &local_aliases,
                ));
            }
            "while_statement" => {
                // Check for unbounded pointer increment in while loops
                violations.extend(self.check_while_loop_pointer_increment(
                    node,
                    source,
                    &local_buffers,
                ));
                // Taint-gated unbounded decode-loop over untrusted blob/column
                // bytes (task 172).
                violations.extend(self.check_unbounded_decode_loop(node, source));
                // Param-decoder index over-read: const-char* parameter walked by
                // an embedded-increment subscript with no length bound (task 210).
                violations.extend(self.check_param_decode_overread(node, source));
            }
            "for_statement" | "do_statement" => {
                violations.extend(self.check_unbounded_decode_loop(node, source));
                violations.extend(self.check_param_decode_overread(node, source));
            }
            "function_definition" => {
                // Task 389: reset to the file-scope-only base (globals,
                // struct/union member arrays, typedef-array members) rather
                // than additively prescanning onto whatever buffer state
                // was inherited from the parent scope — that inherited
                // state may hold a *different* function's same-named local
                // buffer (e.g. two functions each with their own `char
                // buf[N]` of different sizes), which would otherwise leak
                // into this function's violation messages (wrong size,
                // wrong allocation_line). Then pre-scan just this
                // function's own body for its own buffer declarations and
                // malloc assignments, so buffers allocated in nested scopes
                // (if-blocks, loops) are visible to sibling scopes for
                // overflow checks — scoped to this function alone.
                local_buffers = self.global_scope_buffers.borrow().clone();
                // Task 555: a parameter's name (e.g. `buf`) can collide with
                // an unrelated global-scope buffer of the same name -- a
                // struct/union member array, a typedef-array member, or a
                // global variable declared in a completely different part of
                // the file. No source in this file ever legitimately inserts
                // a *parameter*'s own size into `buffers` (only "declaration"
                // nodes are tracked, never "parameter_declaration"), so any
                // hit under a parameter's name here is always that
                // collision, not real size info for the parameter -- e.g.
                // hostap's `wpas_p2ps_get_feat_cap_str(char *buf, ...)` was
                // linked to an unrelated struct's `u8 buf[0]` flexible-array
                // member from a different function entirely. Strip those
                // names from the base map before layering this function's
                // own local declarations back on, so a real local buffer
                // that happens to shadow a parameter name (rare, but valid
                // C) is still tracked correctly.
                for param_name in collect_param_names(node, source) {
                    local_buffers.remove(&param_name);
                }
                if let Some(body) = node.child_by_field_name("body") {
                    let typedefs = self.cached_typedefs.borrow();
                    self.extract_buffers_from_ast(
                        &body,
                        source,
                        &mut local_buffers,
                        &typedefs,
                        macro_constants,
                        true,
                    );
                }
                // Check for malloc/calloc/realloc without proper NULL checks
                violations.extend(self.check_malloc_null_pointer_arithmetic(node, source));
                // Check for insufficient malloc of flexible array structs
                violations.extend(self.check_flexible_array_malloc(
                    node,
                    source,
                    flexible_array_structs,
                ));
            }
            _ => {}
        }

        // Recursively check children, accumulating declarations as we go
        // This ensures declarations are visible to subsequent siblings
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.update_local_state_from_child(
                    &child,
                    source,
                    &mut local_buffers,
                    &mut local_aliases,
                );

                // Recursively check this child with the accumulated context
                violations.extend(self.check_with_buffer_info(
                    &child,
                    source,
                    &local_buffers,
                    &local_aliases,
                    function_macros,
                    flexible_array_structs,
                    macro_constants,
                ));
            }
        }

        violations
    }

    /// Update `local_buffers`/`local_aliases` with any declaration, malloc/realloc
    /// assignment, or simple pointer-alias assignment carried by `child`, so a
    /// sibling visited later in the same `check_with_buffer_info` recursion sees it.
    fn update_local_state_from_child(
        &self,
        child: &Node,
        source: &str,
        local_buffers: &mut HashMap<String, BufferInfo>,
        local_aliases: &mut HashMap<String, PointerAlias>,
    ) {
        // Extract declarations from this child if it's a declaration node
        if child.kind() == "declaration" {
            if let Some(new_buffer) = self.extract_buffer_from_declaration(child, source) {
                // Only insert if not already tracked (line-based analysis takes precedence for realloc tracking)
                if !local_buffers.contains_key(&new_buffer.name) {
                    local_buffers.insert(new_buffer.name.clone(), new_buffer);
                }
            }
            if let Some(new_alias) =
                self.extract_alias_from_declaration(child, source, local_buffers)
            {
                local_aliases.insert(new_alias.alias_name.clone(), new_alias);
            }
        }

        // Track malloc/realloc assignments (e.g., matrix[i] = malloc(...) or ptr = realloc(ptr, size))
        // Check both assignment_expression nodes and their parents (expression_statement)
        let assignment_node = if child.kind() == "assignment_expression" {
            Some(*child)
        } else if child.kind() == "expression_statement" {
            // Look for assignment_expression child
            child
                .child(0)
                .filter(|c| c.kind() == "assignment_expression")
        } else {
            None
        };

        if let Some(assign_node) = assignment_node {
            if let Some((buf_name, buf_info)) =
                self.extract_buffer_from_assignment(&assign_node, source)
            {
                // Insert or update the buffer entry
                local_buffers.insert(buf_name, buf_info);
            }

            // Track pointer aliases from simple assignments: data = dataBadBuffer
            if let (Some(left), Some(right)) = (
                assign_node.child_by_field_name("left"),
                assign_node.child_by_field_name("right"),
            ) {
                if left.kind() == "identifier" && right.kind() == "identifier" {
                    let lhs = &source[left.start_byte()..left.end_byte()];
                    let rhs = &source[right.start_byte()..right.end_byte()];
                    if local_buffers.contains_key(rhs) {
                        local_aliases.insert(
                            lhs.to_string(),
                            PointerAlias {
                                alias_name: lhs.to_string(),
                                original_buffer: rhs.to_string(),
                                element_size_bytes: None,
                            },
                        );
                    }
                }
            }
        }
    }

    /// Extract buffer information from a declaration AST node (with typedef support)
    fn extract_buffer_from_declaration_with_typedefs(
        &self,
        node: &Node,
        source: &str,
        typedefs: &HashMap<String, usize>,
    ) -> Option<BufferInfo> {
        // Look for declarator nodes that contain array or pointer declarations
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "init_declarator" => {
                        // Handles: int arr[5] = {...};
                        return self.extract_buffer_from_init_declarator_with_typedefs(
                            &child, source, typedefs,
                        );
                    }
                    "array_declarator" => {
                        // Handles: int arr[5];
                        return self.extract_buffer_from_array_declarator(&child, source);
                    }
                    // For function pointer arrays like void (*functions[3])(void)
                    // the array_declarator is nested inside function_declarator
                    "function_declarator" | "pointer_declarator" => {
                        // Recursively search for array_declarator
                        if let Some(buffer) = self.find_array_declarator_in_node(&child, source) {
                            return Some(buffer);
                        }
                    }
                    _ => {}
                }
            }
        }
        None
    }

    /// Recursively search for array_declarator in a node tree
    fn find_array_declarator_in_node(&self, node: &Node, source: &str) -> Option<BufferInfo> {
        if node.kind() == "array_declarator" {
            return self.extract_buffer_from_array_declarator(node, source);
        }

        // Recursively search children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(buffer) = self.find_array_declarator_in_node(&child, source) {
                    return Some(buffer);
                }
            }
        }
        None
    }

    /// Extract buffer information from a declaration AST node (without typedefs)
    fn extract_buffer_from_declaration(&self, node: &Node, source: &str) -> Option<BufferInfo> {
        // Look for declarator nodes that contain array or pointer declarations
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "init_declarator" => {
                        // Handles: int arr[5] = {...};
                        return self.extract_buffer_from_init_declarator(&child, source);
                    }
                    "array_declarator" => {
                        // Handles: int arr[5];
                        return self.extract_buffer_from_array_declarator(&child, source);
                    }
                    _ => {}
                }
            }
        }
        None
    }

    /// Extract buffer from init_declarator node (declarations with initializers, with typedef support)
    fn extract_buffer_from_init_declarator_with_typedefs(
        &self,
        node: &Node,
        source: &str,
        typedefs: &HashMap<String, usize>,
    ) -> Option<BufferInfo> {
        // First child is the declarator
        let declarator = node.child(0)?;

        if declarator.kind() == "array_declarator" {
            return self.extract_buffer_from_array_declarator(&declarator, source);
        } else if declarator.kind() == "function_declarator" {
            // For function pointer arrays like: void (*functions[3])(void) = {...}
            // the array_declarator is nested inside function_declarator
            return self.find_array_declarator_in_node(&declarator, source);
        } else if declarator.kind() == "pointer_declarator" {
            // Check if this is a malloc/calloc/alloca assignment
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "call_expression" {
                        return self.extract_buffer_from_malloc_call(&declarator, &child, source);
                    }
                    // Handle cast expression wrapping allocation: (type *)ALLOCA(...)
                    if child.kind() == "cast_expression" {
                        if let Some(call) = self.find_call_in_cast(&child) {
                            return self.extract_buffer_from_malloc_call(
                                &declarator,
                                &call,
                                source,
                            );
                        }
                    }
                }
            }
        } else if declarator.kind() == "identifier" {
            // Simple identifier - could be typedef usage
            let var_name = &source[declarator.start_byte()..declarator.end_byte()];

            // Check if this declaration has an initializer that's a call_expression (malloc)
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "call_expression" {
                        return self.extract_buffer_from_malloc_call(&declarator, &child, source);
                    }
                    // Handle cast expression wrapping allocation: (type *)ALLOCA(...)
                    if child.kind() == "cast_expression" {
                        if let Some(call) = self.find_call_in_cast(&child) {
                            return self.extract_buffer_from_malloc_call(
                                &declarator,
                                &call,
                                source,
                            );
                        }
                    }
                }
            }

            // Could be a typedef array - check parent declaration for type
            if let Some(parent) = node.parent() {
                if parent.kind() == "declaration" {
                    return self.check_typedef_declaration(&parent, var_name, source, typedefs);
                }
            }
        }

        None
    }

    /// Extract buffer from init_declarator node (declarations with initializers, without typedefs)
    fn extract_buffer_from_init_declarator(&self, node: &Node, source: &str) -> Option<BufferInfo> {
        // First child is the declarator
        let declarator = node.child(0)?;

        if declarator.kind() == "array_declarator" {
            return self.extract_buffer_from_array_declarator(&declarator, source);
        } else if declarator.kind() == "pointer_declarator" {
            // Check if this is a malloc/calloc/alloca assignment
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "call_expression" {
                        return self.extract_buffer_from_malloc_call(&declarator, &child, source);
                    }
                    // Handle cast expression wrapping allocation: (type *)ALLOCA(...)
                    if child.kind() == "cast_expression" {
                        if let Some(call) = self.find_call_in_cast(&child) {
                            return self.extract_buffer_from_malloc_call(
                                &declarator,
                                &call,
                                source,
                            );
                        }
                    }
                }
            }
        } else if declarator.kind() == "identifier" {
            // Simple identifier - could be typedef usage
            let var_name = &source[declarator.start_byte()..declarator.end_byte()];

            // Check if this declaration has an initializer that's a call_expression (malloc)
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "call_expression" {
                        return self.extract_buffer_from_malloc_call(&declarator, &child, source);
                    }
                    // Handle cast expression wrapping allocation: (type *)ALLOCA(...)
                    if child.kind() == "cast_expression" {
                        if let Some(call) = self.find_call_in_cast(&child) {
                            return self.extract_buffer_from_malloc_call(
                                &declarator,
                                &call,
                                source,
                            );
                        }
                    }
                }
            }

            // Could be a typedef array - check parent declaration for type (fallback without typedef cache)
            if let Some(parent) = node.parent() {
                if parent.kind() == "declaration" {
                    // Create empty typedefs map for fallback
                    let empty_typedefs = HashMap::new();
                    return self.check_typedef_declaration(
                        &parent,
                        var_name,
                        source,
                        &empty_typedefs,
                    );
                }
            }
        }

        None
    }

    /// Extract buffer info from array_declarator
    /// For multidimensional arrays, extracts the INNERMOST dimension (the base array)
    /// The caller is responsible for extracting outer dimensions
    fn extract_buffer_from_array_declarator(
        &self,
        node: &Node,
        source: &str,
    ) -> Option<BufferInfo> {
        // Check if first child is a nested array_declarator (multidimensional array)
        if let Some(first_child) = node.child(0) {
            if first_child.kind() == "array_declarator" {
                // This is a multidimensional array like int matrix[3][4]
                // The nested array_declarator contains the outer dimension (3)
                // This node contains the inner dimension (4)
                // We should extract from the nested one to get the base buffer
                return self.extract_buffer_from_array_declarator(&first_child, source);
            }
        }

        // Single-dimensional array or innermost dimension of multidimensional array
        let mut var_name: Option<String> = None;
        let mut size: Option<usize> = None;
        let mut size_expr: Option<String> = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    // `field_identifier` is the same declarator-name position
                    // as `identifier`, but that's the node kind tree-sitter-c
                    // uses for a struct/union member's own name (a
                    // `field_declaration`'s array_declarator, e.g. `Matrix
                    // stack[N];` inside a struct body) -- distinct from a
                    // top-level `declaration`'s plain `identifier`. Without
                    // this, the member's name was never captured, and if the
                    // array size was itself a bare identifier (a macro name,
                    // not yet expanded here), IT got misread as the "name"
                    // instead, silently dropping the buffer entirely
                    // (task 235; real example: raylib's rlgl.h `Matrix
                    // stack[RL_MAX_MATRIX_STACK_SIZE];`).
                    "identifier" | "field_identifier" => {
                        if var_name.is_none() {
                            var_name =
                                Some(source[child.start_byte()..child.end_byte()].to_string());
                        } else if i > 0 {
                            // This is the size expression (VLA)
                            let expr = &source[child.start_byte()..child.end_byte()];
                            size_expr = Some(expr.to_string());
                        }
                    }
                    "number_literal" => {
                        let size_str = &source[child.start_byte()..child.end_byte()];
                        size = size_str.parse().ok();
                    }
                    // Handle binary expressions like 10+1 in array size declarations
                    "binary_expression" => {
                        let expr_text = &source[child.start_byte()..child.end_byte()];
                        if let Some(val) = buffer_size::evaluate_simple_arithmetic(expr_text) {
                            if val >= 0 {
                                size = Some(val as usize);
                            }
                        } else {
                            size_expr = Some(expr_text.to_string());
                        }
                    }
                    // Handle parenthesized expressions like (10+1) in array sizes
                    "parenthesized_expression" => {
                        let expr_text = &source[child.start_byte()..child.end_byte()];
                        let inner = expr_text.trim_start_matches('(').trim_end_matches(')');
                        if let Some(val) = buffer_size::evaluate_simple_arithmetic(inner) {
                            if val >= 0 {
                                size = Some(val as usize);
                            }
                        }
                    }
                    // Handle complex declarators (function pointers, nested pointers, etc.)
                    "function_declarator" | "pointer_declarator" | "parenthesized_declarator"
                        if var_name.is_none() =>
                    {
                        var_name = find_identifier_in_declarator(&child, source);
                    }
                    _ => {}
                }
            }
        }

        let name = var_name?;
        let line = node.start_position().row + 1;

        if let Some(s) = size {
            Some(BufferInfo {
                name,
                size: BufferSize::Static(s),
                element_type: "unknown".to_string(),
                allocation_line: line,
                alloc_bytes: None,
            })
        } else {
            size_expr.map(|expr| BufferInfo {
                name,
                size: BufferSize::Symbolic(expr),
                element_type: "unknown".to_string(),
                allocation_line: line,
                alloc_bytes: None,
            })
        }
    }

    /// Extract multidimensional array buffers
    /// For int matrix[3][4], creates:
    /// - "matrix" with size 3 (already created by extract_buffer_from_array_declarator)
    /// - "matrix[*]" with size 4 (created here for inner dimension checking)
    fn extract_multidimensional_buffers(
        &self,
        decl_node: &Node,
        base_name: &str,
        source: &str,
        buffers: &mut HashMap<String, BufferInfo>,
        macros: &HashMap<String, i64>,
    ) {
        // Find the array_declarator in the declaration
        for i in 0..decl_node.child_count() {
            if let Some(child) = decl_node.child(i) {
                if child.kind() == "array_declarator" || child.kind() == "init_declarator" {
                    // Found the declarator - extract inner dimensions
                    self.extract_inner_dimensions(&child, base_name, source, buffers, macros);
                    return;
                }
            }
        }
    }

    /// Recursively extract inner dimensions from array_declarator nodes
    /// For int matrix[3][4], when called on the outer array_declarator:
    /// - Creates "matrix[*]" with size 4
    fn extract_inner_dimensions(
        &self,
        node: &Node,
        base_name: &str,
        source: &str,
        buffers: &mut HashMap<String, BufferInfo>,
        macros: &HashMap<String, i64>,
    ) {
        if node.kind() == "init_declarator" {
            // Skip to the declarator child
            if let Some(declarator) = node.child(0) {
                self.extract_inner_dimensions(&declarator, base_name, source, buffers, macros);
            }
            return;
        }

        if node.kind() != "array_declarator" {
            return;
        }

        // Check if first child is a nested array_declarator
        if let Some(first_child) = node.child(0) {
            if first_child.kind() == "array_declarator" {
                // This node represents an outer dimension (e.g., [COLS] in matrix[ROWS][COLS])
                // Extract the size from THIS node (the outer/rightmost dimension)
                // For matrix[ROWS][COLS], the AST is: array_declarator[COLS] -> array_declarator[ROWS]
                // We want the COLS dimension (rightmost), which is in the current node
                if let Some(mut size) = self.extract_array_size(node, source) {
                    // Resolve macro constants in buffer size
                    if let BufferSize::Symbolic(ref sym) = size {
                        if let Some(&value) = macros.get(sym) {
                            size = BufferSize::Static(value as usize);
                        }
                    }

                    // Create wildcard entry
                    let wildcard_name = format!("{}[*]", base_name);
                    let line = node.start_position().row + 1;

                    buffers.insert(
                        wildcard_name,
                        BufferInfo {
                            name: base_name.to_string(),
                            size,
                            element_type: "array_element".to_string(),
                            allocation_line: line,
                            alloc_bytes: None,
                        },
                    );
                }

                // Continue recursing for deeper dimensions (e.g., int arr[2][3][4])
                self.extract_inner_dimensions(&first_child, base_name, source, buffers, macros);
            }
        }
    }

    /// Extract the size from an array_declarator node
    fn extract_array_size(&self, node: &Node, source: &str) -> Option<BufferSize> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "number_literal" {
                    let size_str = &source[child.start_byte()..child.end_byte()];
                    if let Ok(size) = size_str.parse::<usize>() {
                        return Some(BufferSize::Static(size));
                    }
                } else if child.kind() == "identifier" && i > 0 {
                    // VLA with symbolic size
                    let expr = &source[child.start_byte()..child.end_byte()];
                    return Some(BufferSize::Symbolic(expr.to_string()));
                }
            }
        }
        None
    }

    /// Extract buffer from malloc/calloc call
    fn extract_buffer_from_malloc_call(
        &self,
        declarator: &Node,
        call_node: &Node,
        source: &str,
    ) -> Option<BufferInfo> {
        let var_name = if declarator.kind() == "pointer_declarator" {
            // Navigate to the identifier within pointer_declarator (may be nested for double pointers)
            find_identifier_in_declarator(declarator, source)?
        } else {
            source[declarator.start_byte()..declarator.end_byte()].to_string()
        };

        // Get function name
        let func_name_node = call_node.child(0)?;
        let func_name = &source[func_name_node.start_byte()..func_name_node.end_byte()];

        // Find argument_list
        for i in 0..call_node.child_count() {
            if let Some(child) = call_node.child(i) {
                if child.kind() == "argument_list" {
                    return self.parse_malloc_arguments(
                        func_name,
                        &child,
                        source,
                        &var_name,
                        call_node.start_position().row + 1,
                    );
                }
            }
        }

        None
    }

    /// Find call_expression inside a cast_expression (e.g., (int *)ALLOCA(100))
    fn find_call_in_cast<'a>(&self, cast_node: &Node<'a>) -> Option<Node<'a>> {
        for i in 0..cast_node.child_count() {
            if let Some(child) = cast_node.child(i) {
                if child.kind() == "call_expression" {
                    return Some(child);
                }
            }
        }
        None
    }

    /// Parse malloc/calloc/realloc arguments from argument_list node
    fn parse_malloc_arguments(
        &self,
        func_name: &str,
        arg_list: &Node,
        source: &str,
        var_name: &str,
        line: usize,
    ) -> Option<BufferInfo> {
        match func_name {
            "malloc" | "alloca" | "ALLOCA" => {
                // Get first argument
                for i in 0..arg_list.child_count() {
                    if let Some(child) = arg_list.child(i) {
                        if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                            let arg_text = &source[child.start_byte()..child.end_byte()];
                            let alloc_bytes = buffer_size::calculate_alloc_bytes(arg_text);
                            let size = buffer_size::calculate_malloc_size(arg_text)?;
                            return Some(BufferInfo {
                                name: var_name.to_string(),
                                size,
                                element_type: "unknown".to_string(),
                                allocation_line: line,
                                alloc_bytes,
                            });
                        }
                    }
                }
            }
            "realloc" => {
                // Get second argument (size) - first arg is the old pointer
                let mut args = Vec::new();
                for i in 0..arg_list.child_count() {
                    if let Some(child) = arg_list.child(i) {
                        if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                            args.push(&source[child.start_byte()..child.end_byte()]);
                        }
                    }
                }
                if args.len() >= 2 {
                    let alloc_bytes = buffer_size::calculate_alloc_bytes(args[1]);
                    let size = buffer_size::calculate_malloc_size(args[1])?;
                    return Some(BufferInfo {
                        name: var_name.to_string(),
                        size,
                        element_type: "unknown".to_string(),
                        allocation_line: line,
                        alloc_bytes,
                    });
                }
            }
            "calloc" => {
                // Get first argument (count)
                let mut args = Vec::new();
                for i in 0..arg_list.child_count() {
                    if let Some(child) = arg_list.child(i) {
                        if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                            args.push(&source[child.start_byte()..child.end_byte()]);
                        }
                    }
                }
                if args.len() >= 2 {
                    if let Some(count) = buffer_size::extract_numeric_value(args[0]) {
                        if let Some(sizeof_val) = buffer_size::extract_sizeof_value(args[1]) {
                            return Some(BufferInfo {
                                name: var_name.to_string(),
                                size: BufferSize::DynamicCalculated(count),
                                element_type: "unknown".to_string(),
                                allocation_line: line,
                                alloc_bytes: Some(count * sizeof_val),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
        None
    }

    /// Check if a declaration uses a typedef array type
    fn check_typedef_declaration(
        &self,
        decl_node: &Node,
        var_name: &str,
        source: &str,
        typedefs: &HashMap<String, usize>,
    ) -> Option<BufferInfo> {
        // Get type from declaration
        for i in 0..decl_node.child_count() {
            if let Some(child) = decl_node.child(i) {
                if child.kind() == "type_identifier" {
                    let type_name = &source[child.start_byte()..child.end_byte()];

                    // Check if this type is in our cached typedefs
                    if let Some(&size) = typedefs.get(type_name) {
                        return Some(BufferInfo {
                            name: var_name.to_string(),
                            size: BufferSize::Static(size),
                            element_type: type_name.to_string(),
                            allocation_line: decl_node.start_position().row + 1,
                            alloc_bytes: None,
                        });
                    }
                }
            }
        }
        None
    }

    /// Extract pointer alias from declaration AST node
    fn extract_alias_from_declaration(
        &self,
        node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
    ) -> Option<PointerAlias> {
        // Look for init_declarator with pointer assignment
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "init_declarator" {
                    return self.extract_alias_from_init_declarator(&child, source, buffers);
                }
            }
        }
        None
    }

    /// Extract alias from init_declarator
    fn extract_alias_from_init_declarator(
        &self,
        node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
    ) -> Option<PointerAlias> {
        // First, check for cast expression (int *ptr = (int *)buffer)
        let mut declarator_child: Option<Node> = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "pointer_declarator" || child.kind() == "identifier" {
                    declarator_child = Some(child);
                } else if child.kind() == "cast_expression" {
                    if let Some(decl) = declarator_child {
                        return self.extract_alias_from_cast(&decl, &child, source, buffers);
                    }
                }
            }
        }

        // Check for direct assignment (int *ptr = buffer)
        if let Some(declarator) = node.child(0) {
            // Look for assigned value
            for i in 1..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" {
                        let ptr_name = find_identifier_in_declarator(&declarator, source)?;
                        let buf_name = &source[child.start_byte()..child.end_byte()];

                        if buffers.contains_key(buf_name) {
                            return Some(PointerAlias {
                                alias_name: ptr_name,
                                original_buffer: buf_name.to_string(),
                                element_size_bytes: None,
                            });
                        }
                    }
                }
            }
        }

        None
    }

    /// Extract alias from cast expression
    fn extract_alias_from_cast(
        &self,
        declarator: &Node,
        cast_node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
    ) -> Option<PointerAlias> {
        let ptr_name = find_identifier_in_declarator(declarator, source)?;

        // Get cast type
        let mut cast_type: Option<&str> = None;
        let mut target: Option<&str> = None;

        for i in 0..cast_node.child_count() {
            if let Some(child) = cast_node.child(i) {
                match child.kind() {
                    "type_descriptor" => {
                        // Extract type from type_descriptor
                        for j in 0..child.child_count() {
                            if let Some(type_node) = child.child(j) {
                                if type_node.kind() == "primitive_type" {
                                    cast_type =
                                        Some(&source[type_node.start_byte()..type_node.end_byte()]);
                                }
                            }
                        }
                    }
                    "identifier" => {
                        target = Some(&source[child.start_byte()..child.end_byte()]);
                    }
                    _ => {}
                }
            }
        }

        if let (Some(cast_t), Some(buf_name)) = (cast_type, target) {
            if buffers.contains_key(buf_name) {
                let elem_size = match cast_t {
                    "char" => Some(1),
                    "short" => Some(2),
                    "int" => Some(4),
                    "long" => Some(8),
                    "float" => Some(4),
                    "double" => Some(8),
                    _ => None,
                };

                return Some(PointerAlias {
                    alias_name: ptr_name,
                    original_buffer: buf_name.to_string(),
                    element_size_bytes: elem_size,
                });
            }
        }

        None
    }

    // Removed: extract_identifier_from_declarator - now using ast_utils::find_identifier_in_declarator

    /// Check for dangerous library function calls that can cause buffer overflows
    fn check_dangerous_function_call(
        &self,
        node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Get function name
        if let Some(func_name_node) = node.child(0) {
            let func_name = &source[func_name_node.start_byte()..func_name_node.end_byte()];

            match func_name {
                "strcpy" | "wcscpy" => violations.extend(self.check_strcpy(node, source, buffers)),
                "strcat" => violations.extend(self.check_strcat(node, source, buffers)),
                "memcpy" | "memmove" | "wmemcpy" | "wmemmove" => {
                    violations.extend(self.check_memcpy(node, source, buffers))
                }
                "strncpy" | "wcsncpy" => {
                    violations.extend(self.check_strncpy(node, source, buffers))
                }
                "sprintf" => violations.extend(self.check_sprintf(node, source, buffers)),
                "gets" => violations.extend(self.check_gets(node, source, buffers)),
                _ => {}
            }
        }

        violations
    }

    /// Check for macro invocations that might involve array access
    /// Since macros are not expanded, we flag them for manual review if they:
    /// 1. Match a known function-like macro definition
    /// 2. Take arguments that include tracked buffer names
    fn check_macro_invocation(
        &self,
        node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
        function_macros: &HashMap<String, FunctionMacro>,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Get the function/macro name
        if let Some(func_name_node) = node.child(0) {
            let func_name = &source[func_name_node.start_byte()..func_name_node.end_byte()];

            // Check if this matches a known function-like macro
            if let Some(macro_info) = function_macros.get(func_name) {
                // Check if the macro body contains array subscript syntax
                if macro_info.body.contains('[') && macro_info.body.contains(']') {
                    // Get the arguments to see if any are tracked buffers
                    if let Some(args) = self.get_function_arguments(node, source) {
                        let mut involves_buffer = false;
                        for arg in &args {
                            let arg_name = arg.trim();
                            if buffers.contains_key(arg_name) {
                                involves_buffer = true;
                                break;
                            }
                        }

                        // Flag for manual review ONLY when the array-indexing
                        // macro is invoked on a buffer ARR30 actually tracks.
                        // The former `|| !args.is_empty()` fired on every
                        // array-indexing macro call regardless of whether any
                        // tracked buffer was involved — pure manual-review noise
                        // (e.g. md5/sha round macros over fixed local state).
                        // Migrating to the shared cross-region macro collector
                        // exposed many more such macros, so this guard is what
                        // keeps the migration a precision win; the genuine
                        // out-of-bounds-on-a-tracked-buffer case (Juliet
                        // testcases_macro_over.c) still flags.
                        if involves_buffer {
                            let start_point = node.start_position();
                            violations.push(RuleViolation {
                                rule_id: "ARR30-C".to_string(),
                                severity: Severity::Medium,
                                message: format!(
                                    "Macro '{}' may generate array access that cannot be statically analyzed. Macro body: '{}'. Manual review required to ensure bounds safety",
                                    func_name,
                                    macro_info.body
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some(
                                    "Manually verify that macro expansion does not create out-of-bounds access"
                                        .to_string(),
                                ),
                                requires_manual_review: Some(true),
                            });
                        }
                    }
                }
            }
        }

        violations
    }

    /// Check strcpy calls for buffer overflow potential
    fn check_strcpy(
        &self,
        node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // strcpy(dest, src) - arguments are in argument_list node
        if let Some(args) = self.get_function_arguments(node, source) {
            if args.len() >= 2 {
                let dest_name = args[0].trim();
                let src_text = args[1].trim();

                // Check if destination is a tracked buffer
                if let Some(dest_info) = buffers.get(dest_name) {
                    // Provably safe by source content length: when the source
                    // buffer was filled by a memset whose content (+ null
                    // terminator) fits the destination, the copy cannot
                    // overflow. This is the actual string length written, which
                    // is more precise than the source buffer's capacity — the
                    // distinction that keeps the bad-section overflow (fill >
                    // dest) flagged while suppressing the good-section copy.
                    //
                    // Restricted to Static (stack-array) destinations: the
                    // buffers map is file-wide, so a malloc'd pointer reused
                    // across functions (DynamicCalculated) can carry another
                    // function's size and make this comparison unsound.
                    if let BufferSize::Static(dest_s) = dest_info.size {
                        if let Some(content_len) =
                            buffer_size::memset_content_length(src_text, source, node)
                        {
                            if dest_s > content_len {
                                return violations;
                            }
                        }
                    }

                    // Check if source is a string literal or tracked buffer
                    let src_size = if src_text.starts_with('"') {
                        // String literal - count characters (rough estimate)
                        Some(src_text.len() - 2) // Subtract quotes, actual length may vary
                    } else if let Some(src_info) = buffers.get(src_text) {
                        // Source is also a tracked buffer
                        match src_info.size {
                            BufferSize::Static(s) | BufferSize::DynamicCalculated(s) => Some(s),
                            _ => None,
                        }
                    } else {
                        None
                    };

                    // If we know both sizes, check if source is larger
                    if let Some(src_s) = src_size {
                        if let BufferSize::Static(dest_s) | BufferSize::DynamicCalculated(dest_s) =
                            dest_info.size
                        {
                            if src_s > dest_s {
                                violations.push(self.create_library_violation(
                                    node,
                                    dest_name,
                                    dest_info,
                                    &format!(
                                        "strcpy may overflow: source size {} > destination size {}",
                                        src_s, dest_s
                                    ),
                                ));
                                return violations;
                            }
                        }
                    }

                    // Even if we can't determine exact sizes, strcpy is inherently unsafe
                    // Only flag if source is unknown (not a literal) AND destination has
                    // a known size. For Dynamic-sized buffers (e.g., malloc(n*sizeof(char)))
                    // we can't prove overflow, so skip the warning.
                    if !src_text.starts_with('"') && src_size.is_none() {
                        if matches!(
                            dest_info.size,
                            BufferSize::Static(_) | BufferSize::DynamicCalculated(_)
                        ) {
                            violations.push(self.create_library_violation(
                                node,
                                dest_name,
                                dest_info,
                                "strcpy with unknown source size can cause buffer overflow",
                            ));
                        }
                    }
                }
            }
        }

        violations
    }

    /// Check strcat calls for buffer overflow potential
    fn check_strcat(
        &self,
        node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        if let Some(args) = self.get_function_arguments(node, source) {
            if args.len() >= 2 {
                let dest_name = args[0].trim();
                let src_text = args[1].trim();

                if let Some(dest_info) = buffers.get(dest_name) {
                    // Provably safe by source content length: a strcat into a
                    // freshly-emptied destination whose source was memset to a
                    // length that fits cannot overflow. Mirrors the strcpy gate
                    // and matches Juliet's good-section `*_cat` shape (dest = "").
                    // Static-only: see the strcpy gate's note on file-wide
                    // pointer aliasing for DynamicCalculated destinations.
                    if let BufferSize::Static(dest_s) = dest_info.size {
                        if let Some(content_len) =
                            buffer_size::memset_content_length(src_text, source, node)
                        {
                            if dest_s > content_len {
                                return violations;
                            }
                        }
                    }

                    // strcat is dangerous without knowing current string length
                    // Only flag for known-size buffers; Dynamic-sized buffers can't be proven unsafe
                    if matches!(
                        dest_info.size,
                        BufferSize::Static(_) | BufferSize::DynamicCalculated(_)
                    ) {
                        violations.push(self.create_library_violation(
                            node,
                            dest_name,
                            dest_info,
                            "strcat can cause buffer overflow without length checks",
                        ));
                    }
                }
            }
        }

        violations
    }

    /// Check strncpy/wcsncpy calls for buffer overflow potential
    /// strncpy(dest, src, count) — overflow when count > dest size
    fn check_strncpy(
        &self,
        node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // strncpy(dest, src, count)
        if let Some(args) = self.get_function_arguments(node, source) {
            if args.len() >= 3 {
                let dest_name = args[0].trim();
                let count_expr = args[2].trim();

                if let Some(dest_info) = buffers.get(dest_name) {
                    // Provably safe by source content length: when the count is
                    // `strlen(src)`/`wcslen(src)`, the bytes copied equal the
                    // source's actual string length, not its buffer capacity.
                    // If that memset-established length fits the destination the
                    // copy is safe — keeps the bad-section overflow flagged
                    // (fill 100 > dest) while suppressing the good-section copy
                    // (fill 49 fits dest[50]).
                    // Static-only: see the strcpy gate's note on file-wide
                    // pointer aliasing for DynamicCalculated destinations.
                    if let BufferSize::Static(dest_s) = dest_info.size {
                        if let Some(src_var) = strlen_argument(count_expr) {
                            if let Some(content_len) =
                                buffer_size::memset_content_length(src_var, source, node)
                            {
                                if dest_s > content_len {
                                    return violations;
                                }
                            }
                        }
                    }

                    // Try plain numeric count
                    let count = if let Ok(c) = count_expr.parse::<usize>() {
                        Some(c)
                    } else {
                        // Try strlen/wcslen resolution (e.g., strlen(source) + 1)
                        self.resolve_strlen_plus_one(count_expr, buffers)
                    };

                    if let Some(c) = count {
                        if let BufferSize::Static(dest_s) | BufferSize::DynamicCalculated(dest_s) =
                            dest_info.size
                        {
                            if c > dest_s {
                                violations.push(self.create_library_violation(
                                    node,
                                    dest_name,
                                    dest_info,
                                    &format!(
                                        "strncpy copies {} bytes into {}-byte buffer",
                                        c, dest_s
                                    ),
                                ));
                            }
                        }
                        // Also check byte-level for malloc(N) without sizeof
                        if let Some(dest_bytes) = dest_info.alloc_bytes {
                            if c > dest_bytes && violations.is_empty() {
                                violations.push(self.create_library_violation(
                                    node,
                                    dest_name,
                                    dest_info,
                                    &format!(
                                        "strncpy copies {} bytes into {}-byte buffer",
                                        c, dest_bytes
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }

        violations
    }

    /// Check memcpy/memmove calls for buffer overflow potential
    fn check_memcpy(
        &self,
        node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // memcpy(dest, src, count)
        if let Some(args) = self.get_function_arguments(node, source) {
            if args.len() >= 3 {
                let dest_name = args[0].trim();
                let src_name = args[1].trim();
                let count_expr = args[2].trim();

                if let Some(dest_info) = buffers.get(dest_name) {
                    // Try to parse count — handle plain numbers, N*sizeof(T), and sizeof(src) patterns
                    let count = if let Ok(c) = count_expr.parse::<usize>() {
                        Some(c)
                    } else if count_expr.contains("sizeof") && count_expr.contains('*') {
                        // N*sizeof(T) pattern — evaluate as element count
                        if let Some(size) = buffer_size::calculate_malloc_size(count_expr) {
                            match size {
                                BufferSize::Static(s) | BufferSize::DynamicCalculated(s) => Some(s),
                                _ => None,
                            }
                        } else {
                            None
                        }
                    } else if count_expr.contains("sizeof") {
                        // sizeof(src) pattern — use source buffer size
                        if let Some(src_info) = buffers.get(src_name) {
                            match src_info.size {
                                BufferSize::Static(s) | BufferSize::DynamicCalculated(s) => Some(s),
                                _ => None,
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    // Check 1: Element-count comparison (existing logic)
                    let mut already_flagged = false;
                    if let Some(c) = count {
                        if let BufferSize::Static(dest_s) | BufferSize::DynamicCalculated(dest_s) =
                            dest_info.size
                        {
                            if c > dest_s {
                                violations.push(self.create_library_violation(
                                    node,
                                    dest_name,
                                    dest_info,
                                    &format!(
                                        "memcpy copies {} bytes into {}-byte buffer",
                                        c, dest_s
                                    ),
                                ));
                                already_flagged = true;
                            }
                        }
                    }

                    // Check 2: Byte-level comparison (CWE-131 and CWE-193 detection)
                    // This catches cases where element counts match but byte counts don't
                    // (e.g., malloc(10) vs 10*sizeof(int)), and strlen-based count
                    // expressions (e.g., (strlen(src)+1)*sizeof(char))
                    if !already_flagged {
                        if let Some(dest_bytes) = dest_info.alloc_bytes {
                            if let Some(count_bytes) =
                                self.evaluate_count_bytes(count_expr, buffers)
                            {
                                if count_bytes > dest_bytes {
                                    violations.push(self.create_library_violation(
                                        node,
                                        dest_name,
                                        dest_info,
                                        &format!(
                                            "memcpy copies {} bytes into {}-byte buffer",
                                            count_bytes, dest_bytes
                                        ),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        violations
    }

    /// Check sprintf calls (always potentially unsafe)
    fn check_sprintf(
        &self,
        node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        if let Some(args) = self.get_function_arguments(node, source) {
            if !args.is_empty() {
                let dest_name = args[0].trim();

                if let Some(dest_info) = buffers.get(dest_name) {
                    // Only flag for known-size buffers; Dynamic-sized buffers can't be proven unsafe
                    if matches!(
                        dest_info.size,
                        BufferSize::Static(_) | BufferSize::DynamicCalculated(_)
                    ) {
                        violations.push(self.create_library_violation(
                            node,
                            dest_name,
                            dest_info,
                            "sprintf can cause buffer overflow; use snprintf instead",
                        ));
                    }
                }
            }
        }

        violations
    }

    /// Check gets calls (always unsafe)
    fn check_gets(
        &self,
        node: &Node,
        source: &str,
        buffers: &HashMap<String, BufferInfo>,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        if let Some(args) = self.get_function_arguments(node, source) {
            if !args.is_empty() {
                let dest_name = args[0].trim();

                if let Some(dest_info) = buffers.get(dest_name) {
                    violations.push(self.create_library_violation(
                        node,
                        dest_name,
                        dest_info,
                        "gets is inherently unsafe and can cause buffer overflow",
                    ));
                }
            }
        }

        violations
    }

    /// Extract function arguments from a call_expression node
    fn get_function_arguments(&self, node: &Node, source: &str) -> Option<Vec<String>> {
        // Find the argument_list node
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "argument_list" {
                    let mut args = Vec::new();
                    for j in 0..child.child_count() {
                        if let Some(arg_node) = child.child(j) {
                            if arg_node.kind() != "("
                                && arg_node.kind() != ")"
                                && arg_node.kind() != ","
                            {
                                let arg_text = &source[arg_node.start_byte()..arg_node.end_byte()];
                                args.push(arg_text.to_string());
                            }
                        }
                    }
                    return Some(args);
                }
            }
        }
        None
    }

    /// Create a violation for dangerous library function
    fn create_library_violation(
        &self,
        node: &Node,
        buffer_name: &str,
        buffer_info: &BufferInfo,
        message: &str,
    ) -> RuleViolation {
        let start_point = node.start_position();

        let size_info = match &buffer_info.size {
            BufferSize::Static(s) => format!("size {}", s),
            BufferSize::DynamicCalculated(s) => format!("allocated size {}", s),
            BufferSize::Dynamic(expr) => format!("dynamic size ({})", expr),
            BufferSize::Symbolic(var) => format!("VLA size ({})", var),
            BufferSize::Unknown => "unknown size".to_string(),
        };

        RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!("{}: Buffer '{}' with {} (allocated at line {})",
                           message, buffer_name, size_info, buffer_info.allocation_line),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some("Use safer alternatives like strncpy, strncat, snprintf, or fgets with proper size limits.".to_string()),
            ..Default::default()
        }
    }

    /// Get array node from subscript expression
    #[allow(dead_code)]
    fn get_subscript_array<'a>(&self, node: &'a Node<'a>) -> Option<Node<'a>> {
        node.child(0)
    }

    /// Get index node from subscript expression
    fn get_subscript_index<'a>(&self, node: &'a Node<'a>) -> Option<Node<'a>> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() != "[" && child.kind() != "]" && i > 0 {
                    return Some(child);
                }
            }
        }
        None
    }

    /// Check if condition contains safe bounds (< operator, not <=)
    fn condition_contains_safe_bounds(&self, condition_text: &str, index_text: &str) -> bool {
        let trimmed_index = index_text.trim();

        // Check for unsafe <= operator first - this is ALWAYS unsafe for array bounds
        // because it allows accessing the element at index == size, which is out of bounds
        if condition_text.contains(&format!("{} <=", trimmed_index)) {
            return false; // <= is ALWAYS unsafe for array bounds
        }

        // Check for safe < operator
        if condition_text.contains(&format!("{} <", trimmed_index)) {
            return true;
        }

        // Check for reverse condition: size > index (safe)
        if condition_text.contains(&format!("> {}", trimmed_index)) {
            // Make sure it's not >= (which would be unsafe)
            return !condition_text.contains(&format!(">= {}", trimmed_index));
        }

        false
    }

    /// Generic loop bounds check (when index variable is unknown)
    fn check_for_loop_bounds_generic(&self, for_node: &Node, source: &str) -> bool {
        for i in 0..for_node.child_count() {
            if let Some(child) = for_node.child(i) {
                if child.kind() == "binary_expression" || child.kind() == "comparison_expression" {
                    let condition_text = &source[child.start_byte()..child.end_byte()];
                    // Look for any < operator (safe bounds check)
                    if condition_text.contains(" < ") && !condition_text.contains(" <= ") {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Generic if bounds check (when index variable is unknown)
    fn check_if_bounds_generic(&self, if_node: &Node, source: &str) -> bool {
        for i in 0..if_node.child_count() {
            if let Some(child) = if_node.child(i) {
                if child.kind() == "parenthesized_expression" || child.kind() == "binary_expression"
                {
                    let condition_text = &source[child.start_byte()..child.end_byte()];
                    // Look for any < operator (safe bounds check)
                    if condition_text.contains(" < ") && !condition_text.contains(" <= ") {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// Recursively search for a `parameter_list` node inside a declarator subtree.
/// Extract the single argument of a `strlen(VAR)` / `wcslen(VAR)` expression.
/// Returns `None` when `expr` is not a bare strlen/wcslen call (e.g. it has a
/// `+ 1` addend or wraps a more complex argument).
fn strlen_argument(expr: &str) -> Option<&str> {
    let expr = expr.trim();
    let inner = expr
        .strip_prefix("strlen(")
        .or_else(|| expr.strip_prefix("wcslen("))?;
    let arg = inner.strip_suffix(')')?.trim();
    if arg.is_empty() || arg.contains([',', '(', ')']) {
        return None;
    }
    Some(arg)
}

fn find_param_list_node<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "parameter_list" {
        return Some(*node);
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(found) = find_param_list_node(&child) {
                return Some(found);
            }
        }
    }
    None
}
