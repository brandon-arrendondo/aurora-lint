// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::HashMap;
use std::sync::Arc;

use super::super::{CertRule, RuleViolation};
use crate::analyze::check_macros::{collect_macro_definitions, MacroDefinition};
use crate::analyze::const_eval::{
    collect_macro_constants, try_evaluate_text_public, MacroConstantMap,
};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::settings::IntFacts;
use crate::utility::cert_c::ast_utils::{
    enumerator_in_scope, get_node_text, is_likely_macro_constant, resolve_identifier_declarator,
    typedef_definition_in_scope,
};
use crate::utility::cert_c::declarator_utils::{
    inner_declarator, typedef_declarators, TypedefShape,
};
use lang_parsing_substrate::query;
use tree_sitter::Node;

#[derive(Default)]
pub struct Mem05C {
    /// `ProjectContext::macro_definitions` and `macro_constants`: an array
    /// size macro is usually defined in a header.
    project_definitions: RefCell<Arc<HashMap<String, Vec<MacroDefinition>>>>,
    project_constants: RefCell<Arc<MacroConstantMap>>,
    /// The integer data model the settings credit, for folding a macro body.
    data_model: Cell<IntFacts>,
    /// `ProjectContext::typedef_types`, `struct_typedef_aliases` and
    /// `struct_field_types`, for a typedef a header declares.
    project_typedefs: RefCell<Arc<HashMap<String, String>>>,
    project_struct_aliases: RefCell<Arc<HashMap<String, String>>>,
    project_structs: RefCell<Arc<HashMap<String, HashMap<String, String>>>>,
    /// Steps left for the size being read; see [`SIZE_WORK`].
    work_left: Cell<usize>,
    /// Whether a read since this was cleared stopped at the depth cap or
    /// the budget, so its `false` means "not shown", not "not constant".
    cut_short: Cell<bool>,
    /// Per file: whether the object a declarator (by start byte) declares
    /// has a constant size, for answers that were not cut short. A chain of
    /// arrays each sized by `sizeof` of the one before reads each link once.
    fixed_size_objects: RefCell<HashMap<usize, bool>>,
    /// The same for a typedef, by its definition's start byte and the name
    /// it defines: a chain of typedefs each naming the one before twice.
    fixed_size_typedefs: RefCell<HashMap<(usize, String), bool>>,
}

/// The most steps one array size may take to be shown constant. A size whose
/// `sizeof` operands name arrays sized the same way is re-read once per
/// reference, which doubles per level when each level names two; past the
/// budget the size is not shown constant, so it fails toward reporting.
const SIZE_WORK: usize = 4096;

/// What a file's macros and typedefs say about array sizes, read only when
/// a size needs them.
struct FileMacros {
    definitions: HashMap<String, Vec<MacroDefinition>>,
    constants: MacroConstantMap,
    /// Each name a typedef in the file defines, and whether one is in a
    /// block. Only a block can declare a VLA type, so only those names need
    /// the scoped lookup, whose per-call cost grows with the file.
    typedefs: HashMap<String, bool>,
}

impl CertRule for Mem05C {
    fn rule_id(&self) -> &'static str {
        "MEM05-C"
    }
    fn description(&self) -> &'static str {
        "Avoid large stack allocations"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cert_id(&self) -> &'static str {
        "MEM05-C"
    }

    fn set_analysis_settings(&self, settings: &std::sync::Arc<crate::settings::AnalysisSettings>) {
        self.data_model.set(settings.facts);
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_definitions.borrow_mut() = context.macro_definitions.clone();
        *self.project_constants.borrow_mut() = context.macro_constants.clone();
        *self.project_typedefs.borrow_mut() = context.typedef_types.clone();
        *self.project_struct_aliases.borrow_mut() = context.struct_typedef_aliases.clone();
        *self.project_structs.borrow_mut() = context.struct_field_types.clone();
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Mem05C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let file_macros = OnceCell::new();
        self.fixed_size_objects.borrow_mut().clear();
        self.fixed_size_typedefs.borrow_mut().clear();
        for n in query::find_descendants(*node, |_| true) {
            // Look for array declarations with variable size (VLA)
            if n.kind() == "declaration" {
                // Use AST-based detection: look for array_declarator in the declaration.
                // This avoids false positives from array subscripts in initializers
                // (e.g., `uint8_t x = arr[i]` is NOT a VLA, but `uint8_t arr[n]` IS).
                if let Some((size_expr, size_node)) = Self::find_array_declarator_size(&n, source) {
                    let size_expr = size_expr.trim();
                    // A size that is an integer constant expression declares
                    // an ordinary array, whatever its names are spelled like.
                    // A lone ALL_CAPS name no definition in reach resolves is
                    // still taken for a constant, as before.
                    if !size_expr.is_empty()
                        && !size_expr.chars().all(|c| c.is_numeric())
                        && !is_likely_macro_constant(size_expr)
                        && !size_node.is_some_and(|size| {
                            self.work_left.set(SIZE_WORK);
                            self.is_integer_constant_expression(
                                &size,
                                source,
                                &file_macros,
                                node,
                                0,
                            )
                        })
                    {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            line: n.start_position().row + 1,
                            column: n.start_position().column + 1,
                            file_path: String::new(),
                            message: "Variable-length array with runtime-sized allocation; \
                                         use malloc instead"
                                .to_string(),
                            suggestion: Some(
                                "Use malloc/calloc for dynamic allocation".to_string(),
                            ),
                            requires_manual_review: None,
                        });
                    }
                }
            }

            // Check for recursive functions (potential stack overflow)
            if n.kind() == "function_definition" {
                if let Some(func_name) = self.extract_function_name(&n, source) {
                    if let Some(body) = n.child_by_field_name("body") {
                        if Self::body_calls_function(&body, source, &func_name) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                line: n.start_position().row + 1,
                                column: n.start_position().column + 1,
                                file_path: String::new(),
                                message: "Recursive function can cause excessive stack allocation"
                                    .to_string(),
                                suggestion: Some(
                                    "Consider iterative approach or limit recursion depth"
                                        .to_string(),
                                ),
                                requires_manual_review: None,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Returns true if `body` (a compound_statement) contains a direct call to `func_name`.
    /// Uses AST traversal of call_expression nodes to avoid matching occurrences in
    /// string literals, comments, or the function's own declaration.
    fn body_calls_function(node: &Node, source: &str, func_name: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(function) = n.child_by_field_name("function") else {
                return false;
            };
            function.utf8_text(source.as_bytes()).unwrap_or("") == func_name
        })
        .is_some()
    }

    /// Walk a declaration's AST to find an array_declarator and return its size expression,
    /// with the size's node when the parse has one.
    /// Returns None if the declaration doesn't contain an array_declarator (e.g., it's a
    /// scalar declaration like `uint8_t x = arr[i]` where `[i]` is a subscript, not a size).
    fn find_array_declarator_size<'a>(
        decl_node: &Node<'a>,
        source: &str,
    ) -> Option<(String, Option<Node<'a>>)> {
        Self::find_array_size_recursive(decl_node, source)
    }

    fn find_array_size_recursive<'a>(
        node: &Node<'a>,
        source: &str,
    ) -> Option<(String, Option<Node<'a>>)> {
        if node.kind() == "array_declarator" {
            // The array size is the child in brackets, typically the `size` field
            // or the last child before `]`
            if let Some(size_node) = node.child_by_field_name("size") {
                let size_text = size_node
                    .utf8_text(source.as_bytes())
                    .unwrap_or("")
                    .to_string();
                return Some((size_text, Some(size_node)));
            }
            // Fallback: extract text between [ and ]
            let text = node.utf8_text(source.as_bytes()).unwrap_or("");
            if let Some(start) = text.find('[') {
                // Search for the `]` after the `[`: a `]` earlier in the text
                // (in a comment, say) must not reverse the range.
                if let Some(end) = text[start + 1..].find(']') {
                    let size = text[start + 1..start + 1 + end].trim().to_string();
                    if !size.is_empty() {
                        return Some((size, None));
                    }
                }
            }
            return None;
        }
        // Recurse into children but skip init_declarator's value (the initializer)
        // to avoid matching subscript expressions on the RHS of assignments
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                // Skip the value/initializer — subscripts there are NOT array declarations
                if node.kind() == "init_declarator"
                    && node.child_by_field_name("value").map(|v| v.id()) == Some(child.id())
                {
                    continue;
                }
                if let Some(size) = Self::find_array_size_recursive(&child, source) {
                    return Some(size);
                }
            }
        }
        None
    }

    /// Whether `expr`, an array size, is an integer constant expression
    /// (C23 6.6): literals, `sizeof` and `_Alignof`, casts and operators over
    /// constants, enumerators, and names every live definition of which is an
    /// object-like macro that folds to an integer. A name bound to an object
    /// is not one, `const` or not: `const int k = 4; int a[k];` is a VLA.
    fn is_integer_constant_expression(
        &self,
        expr: &Node,
        source: &str,
        file_macros: &OnceCell<FileMacros>,
        root: &Node,
        depth: usize,
    ) -> bool {
        if depth > 64 || self.work_left.get() == 0 {
            self.cut_short.set(true);
            return false;
        }
        self.work_left.set(self.work_left.get() - 1);
        let constant = |child: &Node| {
            self.is_integer_constant_expression(child, source, file_macros, root, depth + 1)
        };
        match expr.kind() {
            // An integer constant, not a floating one: no `.`, and no
            // exponent (`e` in decimal, `p` in hexadecimal, where `e` is a
            // digit).
            "number_literal" => {
                let text = get_node_text(expr, source);
                let hex = text.starts_with("0x") || text.starts_with("0X");
                let exponent: &[char] = if hex { &['p', 'P'] } else { &['e', 'E'] };
                !text.contains('.') && !text.contains(exponent)
            }
            "char_literal" => true,
            // Only the operand's type matters, and it is constant unless the
            // operand is a VLA (C23 6.5.3.4p2). A type operand is constant
            // when each array size it spells, and each one in the typedef it
            // names, is; a string literal or a struct member always is; a
            // name operand when it is a typedef at file scope, or the object
            // it resolves to is declared that way. Any other expression
            // operand, `*p` or `m[0]`, is not shown to be.
            "sizeof_expression" | "alignof_expression" => {
                match expr.child_by_field_name("value") {
                    Some(value) => {
                        let mut inner = value;
                        while inner.kind() == "parenthesized_expression" {
                            match inner.named_child(0) {
                                Some(n) => inner = n,
                                None => break,
                            }
                        }
                        // A string literal has a fixed array type, and a
                        // struct member is never variably modified (C23
                        // 6.7.2.1).
                        if matches!(
                            inner.kind(),
                            "string_literal" | "concatenated_string" | "field_expression"
                        ) {
                            return true;
                        }
                        // `sizeof(T)` for a typedef `T` in scope parses as
                        // a name in parentheses.
                        inner.kind() == "identifier"
                            && match self.block_typedef_in_scope(
                                &inner,
                                get_node_text(&inner, source),
                                file_macros,
                                root,
                                source,
                            ) {
                                Some(definition) => self.is_fixed_size_typedef(
                                    &definition,
                                    get_node_text(&inner, source),
                                    source,
                                    file_macros,
                                    root,
                                    depth,
                                ),
                                None => {
                                    self.names_header_type(&inner, file_macros, root, source)
                                        || self.names_fixed_size_object(
                                            &inner,
                                            source,
                                            file_macros,
                                            root,
                                            depth,
                                        )
                                }
                            }
                    }
                    None => expr.child_by_field_name("type").is_some_and(|ty| {
                        self.is_fixed_size_type(&ty, source, file_macros, root, depth)
                    }),
                }
            }
            "parenthesized_expression" => expr.named_child(0).is_some_and(|inner| constant(&inner)),
            "cast_expression" => expr
                .child_by_field_name("value")
                .is_some_and(|value| constant(&value)),
            "unary_expression" => {
                let operator = expr
                    .child_by_field_name("operator")
                    .map(|op| get_node_text(&op, source))
                    .unwrap_or("");
                matches!(operator, "-" | "+" | "~" | "!")
                    && expr
                        .child_by_field_name("argument")
                        .is_some_and(|argument| constant(&argument))
            }
            "binary_expression" => {
                expr.child_by_field_name("left")
                    .is_some_and(|l| constant(&l))
                    && expr
                        .child_by_field_name("right")
                        .is_some_and(|r| constant(&r))
            }
            "conditional_expression" => {
                ["condition", "consequence", "alternative"]
                    .iter()
                    .all(|field| {
                        expr.child_by_field_name(field)
                            .is_some_and(|c| constant(&c))
                    })
            }
            "identifier" => {
                let name = get_node_text(expr, source);
                if resolve_identifier_declarator(expr, name, source).is_some() {
                    return false;
                }
                enumerator_in_scope(expr, name, source)
                    || self.is_constant_macro(name, file_macros, root, source)
            }
            _ => false,
        }
    }

    /// Whether the name `ident` resolves to an object whose `sizeof` is
    /// constant: every array size in its declarator is constant (`int a[]`
    /// takes its size from the initializer), and so is the type it is
    /// declared with. A name that resolves to no declaration is not shown to
    /// be one.
    fn names_fixed_size_object(
        &self,
        ident: &Node,
        source: &str,
        file_macros: &OnceCell<FileMacros>,
        root: &Node,
        depth: usize,
    ) -> bool {
        let name = get_node_text(ident, source);
        let Some((declaration, declarator)) = resolve_identifier_declarator(ident, name, source)
        else {
            return false;
        };
        if let Some(&known) = self
            .fixed_size_objects
            .borrow()
            .get(&declarator.start_byte())
        {
            return known;
        }
        let outer_cut = self.cut_short.replace(false);
        let fixed = self.array_sizes_constant(&declarator, source, file_macros, root, depth)
            && declaration.child_by_field_name("type").is_none_or(|ty| {
                self.is_fixed_size_specifier(&ty, source, file_macros, root, depth)
            });
        if self.cut_short.get() {
            self.cut_short.set(true);
        } else {
            self.fixed_size_objects
                .borrow_mut()
                .insert(declarator.start_byte(), fixed);
            self.cut_short.set(outer_cut);
        }
        fixed
    }

    /// Whether `ident`, a `sizeof` operand, names a typedef at file scope,
    /// in this file or a scanned header: it resolves to nothing in this
    /// file, no macro in reach defines it, and a file-scope typedef of this
    /// file or the project's typedef tables (scalar or struct-bodied) name
    /// it a type. A typedef at file scope cannot be a VLA, whose type is
    /// declared in a block, so its size is constant. A name no table holds
    /// (an unscanned header's type, or a VLA a macro declares) is not shown
    /// to be one, whatever it is spelled like (ADR-0006).
    fn names_header_type(
        &self,
        ident: &Node,
        file_macros: &OnceCell<FileMacros>,
        root: &Node,
        source: &str,
    ) -> bool {
        let name = get_node_text(ident, source);
        (self
            .file_macros(file_macros, root, source)
            .typedefs
            .get(name)
            == Some(&false)
            || self.project_typedefs.borrow().contains_key(name)
            || self.project_struct_aliases.borrow().contains_key(name)
            || self.project_structs.borrow().contains_key(name))
            && resolve_identifier_declarator(ident, name, source).is_none()
            && !self
                .file_macros(file_macros, root, source)
                .definitions
                .contains_key(name)
            && !self.project_definitions.borrow().contains_key(name)
    }

    /// Whether a `sizeof` type operand, a `type_descriptor`, names a type
    /// of constant size: its abstract declarator's array sizes and its
    /// specifier both are. tree-sitter reads `sizeof(x)` as a type when it
    /// cannot tell, so a lone name that resolves to an object is read as
    /// that object.
    fn is_fixed_size_type(
        &self,
        descriptor: &Node,
        source: &str,
        file_macros: &OnceCell<FileMacros>,
        root: &Node,
        depth: usize,
    ) -> bool {
        let specifier = descriptor.child_by_field_name("type");
        let declarator = descriptor.child_by_field_name("declarator");
        if let (Some(ty), None) = (specifier, declarator) {
            if ty.kind() == "type_identifier" {
                let name = get_node_text(&ty, source);
                if self
                    .block_typedef_in_scope(&ty, name, file_macros, root, source)
                    .is_none()
                    && resolve_identifier_declarator(&ty, name, source).is_some()
                {
                    return self.names_fixed_size_object(&ty, source, file_macros, root, depth);
                }
            }
        }
        declarator.is_none_or(|d| self.array_sizes_constant(&d, source, file_macros, root, depth))
            && specifier.is_none_or(|ty| {
                self.is_fixed_size_specifier(&ty, source, file_macros, root, depth)
            })
    }

    /// Whether a type specifier has a constant size. Only a typedef in this
    /// file can name a VLA type, since one is declared in a block: it is
    /// constant when the declarator that defines the name, and the type it is
    /// defined from, are. A typedef from a header, a builtin or a tag is.
    fn is_fixed_size_specifier(
        &self,
        specifier: &Node,
        source: &str,
        file_macros: &OnceCell<FileMacros>,
        root: &Node,
        depth: usize,
    ) -> bool {
        if depth > 64 {
            self.cut_short.set(true);
            return false;
        }
        if specifier.kind() != "type_identifier" {
            return true;
        }
        let name = get_node_text(specifier, source);
        self.block_typedef_in_scope(specifier, name, file_macros, root, source)
            .is_none_or(|definition| {
                self.is_fixed_size_typedef(&definition, name, source, file_macros, root, depth)
            })
    }

    /// Whether the type `definition`, a `type_definition`, gives `name` has
    /// a constant size: the declarator that defines the name, and the type it
    /// is defined from.
    fn is_fixed_size_typedef(
        &self,
        definition: &Node,
        name: &str,
        source: &str,
        file_macros: &OnceCell<FileMacros>,
        root: &Node,
        depth: usize,
    ) -> bool {
        let key = (definition.start_byte(), name.to_string());
        if let Some(&known) = self.fixed_size_typedefs.borrow().get(&key) {
            return known;
        }
        let outer_cut = self.cut_short.replace(false);
        let fixed = typedef_declarators(definition)
            .iter()
            .filter(|d| TypedefShape::of(d, source).name.as_deref() == Some(name))
            .all(|d| self.array_sizes_constant(d, source, file_macros, root, depth))
            && definition.child_by_field_name("type").is_none_or(|ty| {
                self.is_fixed_size_specifier(&ty, source, file_macros, root, depth + 1)
            });
        if self.cut_short.get() {
            self.cut_short.set(true);
        } else {
            self.fixed_size_typedefs.borrow_mut().insert(key, fixed);
            self.cut_short.set(outer_cut);
        }
        fixed
    }

    /// Whether every array size in a declarator chain, abstract or not, is
    /// an integer constant expression. Only the chain is walked: an array
    /// inside a size (`[sizeof(int[n])]`) is the size's own to read.
    fn array_sizes_constant(
        &self,
        declarator: &Node,
        source: &str,
        file_macros: &OnceCell<FileMacros>,
        root: &Node,
        depth: usize,
    ) -> bool {
        std::iter::successors(Some(*declarator), inner_declarator)
            .filter(|n| matches!(n.kind(), "array_declarator" | "abstract_array_declarator"))
            .all(|array| {
                array.child_by_field_name("size").is_none_or(|size| {
                    self.is_integer_constant_expression(&size, source, file_macros, root, depth + 1)
                })
            })
    }

    fn file_macros<'m>(
        &self,
        file_macros: &'m OnceCell<FileMacros>,
        root: &Node,
        source: &str,
    ) -> &'m FileMacros {
        file_macros.get_or_init(|| {
            let mut typedefs = HashMap::new();
            for definition in query::find_descendants_of_kind(*root, "type_definition") {
                let in_block = std::iter::successors(definition.parent(), Node::parent)
                    .any(|a| a.kind() == "compound_statement");
                for declarator in typedef_declarators(&definition) {
                    if let Some(name) = TypedefShape::of(&declarator, source).name {
                        *typedefs.entry(name).or_insert(false) |= in_block;
                    }
                }
            }
            FileMacros {
                definitions: collect_macro_definitions(source),
                constants: collect_macro_constants(root, source, self.data_model.get()),
                typedefs,
            }
        })
    }

    /// The `type_definition` that makes `name` a type at `at`, when one in a
    /// block may: [`typedef_definition_in_scope`], asked only of a name some
    /// block's typedef defines.
    fn block_typedef_in_scope<'a>(
        &self,
        at: &Node<'a>,
        name: &str,
        file_macros: &OnceCell<FileMacros>,
        root: &Node,
        source: &str,
    ) -> Option<Node<'a>> {
        let file = self.file_macros(file_macros, root, source);
        if file.typedefs.get(name) == Some(&true) {
            typedef_definition_in_scope(at, name, source)
        } else {
            None
        }
    }

    /// Whether every live definition of `name`, in this file's `#if` arms and
    /// across the project, is an object-like macro whose body folds to an
    /// integer, so the name is a constant in every build that defines it.
    /// A name nothing in reach defines is not shown to be one.
    fn is_constant_macro(
        &self,
        name: &str,
        file_macros: &OnceCell<FileMacros>,
        root: &Node,
        source: &str,
    ) -> bool {
        let file = self.file_macros(file_macros, root, source);
        let project_definitions = self.project_definitions.borrow();
        let project_constants = self.project_constants.borrow();
        let mut objects = file
            .definitions
            .get(name)
            .into_iter()
            .chain(project_definitions.get(name))
            .flatten()
            .filter(|def| !matches!(def, MacroDefinition::Function { .. }))
            .peekable();
        objects.peek().is_some()
            && objects.all(|def| match def {
                MacroDefinition::Object { body } => try_evaluate_text_public(body, &file.constants)
                    .or_else(|| try_evaluate_text_public(body, &project_constants))
                    .is_some(),
                _ => false,
            })
    }

    fn extract_function_name(&self, node: &Node, source: &str) -> Option<String> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "function_declarator" {
                let mut inner_cursor = child.walk();
                for inner_child in child.children(&mut inner_cursor) {
                    if inner_child.kind() == "identifier" {
                        return Some(
                            inner_child
                                .utf8_text(source.as_bytes())
                                .unwrap_or("")
                                .to_string(),
                        );
                    }
                }
            }
        }
        None
    }
}
