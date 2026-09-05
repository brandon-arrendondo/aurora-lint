//! Which storage OBJECT a call argument hands to a callee.
//!
//! ARR36-C decides whether two pointer parameters of one function may denote
//! two different arrays. Nothing inside the callee settles that -- the fact
//! lives in the caller -- so the rule reads its call sites and asks, of each
//! argument, "does this expression NAME an object?". An argument names one
//! only when it is a declared array, the address of a non-pointer lvalue, a
//! string or compound literal, or a fresh allocation. A bare pointer variable
//! and `&ptr` name nothing: `f(&pos, end)` passes a cursor and its bound, and
//! which buffer they walk is no more knowable in the caller than in the
//! callee (task 753).
//!
//! Answering that needs the caller's own frame -- which names it declared as
//! arrays, which as pointers, which of its field paths are pointer-typed --
//! so the frame and the predicate live here rather than in the rule: the
//! prescan runs the same code over every translation unit to reach the
//! callers ARR36-C's own file-local pass cannot see (task 936).

use crate::utility::cert_c::{ast_utils, overflow_helpers};
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// What one function's frame knows about the names in scope for it: which
/// denote storage of their own, which merely hold a pointer, and which field
/// paths are pointer-typed.
#[derive(Debug, Default, Clone)]
pub struct ObjectFrame {
    /// Every name DECLARED as a pointer or an array, whether or not anything
    /// is known about its target. Answers "can this name be in an array at
    /// all", which is prior to "which array".
    pub pointer_vars: HashSet<String>,
    /// Names declared with an array declarator -- `char buf[N]` -- and so
    /// naming storage of their own. A pointer variable is NOT in here however
    /// well its target is known, because only a declaration of storage settles
    /// which object an argument hands to a callee.
    pub array_objects: HashSet<String>,
    /// Field paths whose terminal member is POINTER-typed, spelled as they
    /// appear in the source (`pPg->aData`, `cert->tbsCertificate.beg`). Such a
    /// path does not name storage: what a callee compares is the member's
    /// target, which this frame cannot name any better than a pointer
    /// parameter's (task 935).
    pub pointer_members: HashSet<String>,
}

impl ObjectFrame {
    /// An empty frame, knowing nothing about any name.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a name declared with a pointer or array declarator.
    pub fn note_declared(&mut self, name: &str, is_array: bool) {
        self.pointer_vars.insert(name.to_string());
        if is_array {
            self.array_objects.insert(name.to_string());
        }
    }

    /// Record every pointer or array name a `declaration` node introduces.
    pub fn record_declaration(&mut self, node: &Node, source: &str) {
        for declared in declared_pointers(node, source) {
            self.note_declared(&declared.name, declared.is_array);
        }
    }

    /// Record a pointer or array parameter, returning the name recorded.
    ///
    /// An array PARAMETER is not put in `array_objects`: `char buf[]` in a
    /// parameter list is a pointer, and the storage it points at belongs to
    /// whoever called this function.
    pub fn record_parameter(&mut self, node: &Node, source: &str) -> Option<String> {
        if !is_pointer_or_array_parameter(node) {
            return None;
        }
        let declarator = node.child_by_field_name("declarator")?;
        let name = ast_utils::get_identifier_from_declarator(&declarator, source);
        if name.is_empty() {
            return None;
        }
        self.pointer_vars.insert(name.clone());
        Some(name)
    }

    /// Record every field path in `func` whose terminal member is declared as
    /// a POINTER, using whatever struct field types are in scope.
    ///
    /// A path whose type does not resolve is deliberately left out, so it
    /// keeps naming storage. Absence of type information is not evidence that
    /// a member is a pointer, and treating it as such would switch off
    /// ARR36-C-EX1 detection wholesale on every run without cross-file
    /// context (task 935).
    pub fn record_pointer_members(
        &mut self,
        func: &Node,
        source: &str,
        struct_field_types: &HashMap<String, HashMap<String, String>>,
    ) {
        if struct_field_types.is_empty() {
            return;
        }
        let type_map = overflow_helpers::collect_variable_types(func, source);
        for field in query::find_descendants_of_kind(*func, "field_expression") {
            let resolved = ast_utils::resolve_field_expression_type(
                &field,
                source,
                &type_map,
                struct_field_types,
            );
            // `extract_field_decl` spells a pointer member's type with a
            // trailing `*`; an array member keeps the element type alone.
            if resolved.is_some_and(|field_type| field_type.trim_end().ends_with('*')) {
                self.pointer_members
                    .insert(ast_utils::get_node_text(&field, source).to_string());
            }
        }
    }

    /// Record the file-scope declarations of a translation unit: globals and
    /// file-level statics, which are in scope for every function in it.
    /// Only direct children are read, so a declaration inside a function body
    /// is not mistaken for one at file scope.
    pub fn collect_file_scope(&mut self, node: &Node, source: &str) {
        match node.kind() {
            "translation_unit" | "preproc_ifdef" | "preproc_if" | "preproc_else"
            | "preproc_elif" => {
                for i in 0..node.child_count() {
                    let Some(child) = node.child(i) else { continue };
                    if child.kind() == "declaration" {
                        self.record_declaration(&child, source);
                    } else if child.kind().starts_with("preproc_") {
                        self.collect_file_scope(&child, source);
                    }
                }
            }
            _ => {}
        }
    }

    /// Record every declaration and parameter of one function definition.
    pub fn collect_function(&mut self, func: &Node, source: &str) {
        for n in query::find_descendants_of_kinds(*func, &["declaration", "parameter_declaration"])
        {
            match n.kind() {
                "declaration" => self.record_declaration(&n, source),
                "parameter_declaration" => {
                    self.record_parameter(&n, source);
                }
                _ => {}
            }
        }
    }

    /// The storage OBJECT an argument expression hands to a callee, when this
    /// frame can name one.
    ///
    /// `None` for anything whose object this frame cannot name -- above all a
    /// bare pointer variable and `&ptr`. That is the point rather than a
    /// limitation: counting two pointer variables as two objects would
    /// restate one frame up exactly the assumption this is here to remove.
    pub fn argument_object_base(&self, node: &Node, source: &str) -> Option<String> {
        let text = |n: &Node| source[n.start_byte()..n.end_byte()].to_string();
        match node.kind() {
            "identifier" => {
                let name = text(node);
                self.array_objects.contains(&name).then_some(name)
            }
            // Each literal is its own object, as `extract_array_base` has it.
            "string_literal" | "compound_literal_expression" => {
                Some(format!("{}@{}", text(node), node.start_byte()))
            }
            "cast_expression" => {
                self.argument_object_base(&node.child_by_field_name("value")?, source)
            }
            // `arr + n` is still in `arr`.
            "binary_expression" => {
                self.argument_object_base(&node.child_by_field_name("left")?, source)
            }
            "call_expression" => allocation_object(node, source),
            "pointer_expression" | "unary_expression" => {
                let operator = node.child(0)?;
                if ast_utils::get_node_text(&operator, source) != "&" {
                    // `*p` names whatever p points to, which is the unknown.
                    return None;
                }
                self.object_of_lvalue(&node.child_by_field_name("argument")?, source)
            }
            _ => None,
        }
    }

    /// The object an lvalue names, for the `&lvalue` case.
    ///
    /// A pointer variable is excluded even though `&ptr` does name storage:
    /// what the callee then compares is `*param`, whose object is the
    /// pointer's target, not the pointer.
    fn object_of_lvalue(&self, node: &Node, source: &str) -> Option<String> {
        let text = |n: &Node| source[n.start_byte()..n.end_byte()].to_string();
        match node.kind() {
            "identifier" => {
                let name = text(node);
                let names_storage =
                    self.array_objects.contains(&name) || !self.pointer_vars.contains(&name);
                names_storage.then_some(name)
            }
            // Two members of one struct are two objects -- unless the member
            // is a pointer, in which case what the callee compares is its
            // target, which this frame cannot name (task 935).
            "field_expression" => {
                let path = text(node);
                (!self.pointer_members.contains(&path)).then_some(path)
            }
            // `&matrix[i]` is in `matrix`.
            "subscript_expression" => {
                self.object_of_lvalue(&node.child_by_field_name("argument")?, source)
            }
            _ => None,
        }
    }
}

/// One name introduced by a `declaration` node with a pointer or array
/// declarator, with the `init_declarator` child it came from when there is
/// one (which carries the initializer).
pub struct DeclaredPointer<'tree> {
    /// The declared name.
    pub name: String,
    /// True when the declarator is an array declarator, so the name denotes
    /// storage of its own.
    pub is_array: bool,
    /// The `init_declarator` this name came from, when it has an initializer
    /// to read.
    pub init_declarator: Option<Node<'tree>>,
}

/// Every name a `declaration` node introduces with a pointer or array
/// declarator.
///
/// Shared by the frame above and by ARR36-C's own alias tracking so that both
/// agree on which declarations introduce a pointer at all; the rule then reads
/// `init_declarator` for the initializer the frame has no use for.
pub fn declared_pointers<'tree>(node: &Node<'tree>, source: &str) -> Vec<DeclaredPointer<'tree>> {
    let mut declared = Vec::new();
    for i in 0..node.child_count() {
        let Some(child) = node.child(i) else { continue };
        let declarator = if child.kind() == "init_declarator" {
            child.child_by_field_name("declarator")
        } else if is_pointer_declarator(&child) {
            // Bare declarations without initializer: `int nums[SIZE];`, `int *p;`
            Some(child)
        } else {
            None
        };
        let Some(declarator) = declarator else {
            continue;
        };
        if !is_pointer_declarator(&declarator) {
            continue;
        }
        let name = ast_utils::get_identifier_from_declarator(&declarator, source);
        if name.is_empty() {
            continue;
        }
        declared.push(DeclaredPointer {
            name,
            is_array: declarator.kind() == "array_declarator",
            init_declarator: (child.kind() == "init_declarator").then_some(child),
        });
    }
    declared
}

/// Whether a declarator spells a pointer or an array.
pub fn is_pointer_declarator(declarator: &Node) -> bool {
    matches!(declarator.kind(), "pointer_declarator" | "array_declarator")
}

/// Whether a parameter declaration has a pointer or array type. A non-pointer
/// parameter is a scalar, and comparing two of those is not pointer
/// comparison at all.
pub fn is_pointer_or_array_parameter(param_node: &Node) -> bool {
    if let Some(declarator) = param_node.child_by_field_name("declarator") {
        if is_pointer_declarator(&declarator) {
            return true;
        }
        // Nested declarators, e.g. `char *argv[]`.
        for i in 0..declarator.child_count() {
            if let Some(child) = declarator.child(i) {
                if is_pointer_declarator(&child) {
                    return true;
                }
            }
        }
    }
    // Abstract pointer declarators (e.g., `void *` without a name).
    param_node
        .child_by_field_name("type")
        .is_some_and(|type_node| type_node.kind() == "pointer_declarator")
}

/// A fresh allocation is its own object, so two allocation calls are two
/// objects. Mirrors the allocation arm of ARR36-C's `extract_array_base`.
fn allocation_object(node: &Node, source: &str) -> Option<String> {
    let func_node = node.child_by_field_name("function")?;
    let func_name = ast_utils::get_node_text(&func_node, source);
    let canonical = func_name.strip_prefix("os_").unwrap_or(func_name);
    matches!(
        canonical,
        "malloc" | "calloc" | "realloc" | "aligned_alloc" | "alloca"
    )
    .then(|| format!("alloc@{}", node.start_byte()))
}

/// The argument expressions of a call, in order. `argument_list` also holds
/// the parentheses and commas, which are unnamed, and any comment between
/// arguments.
pub fn argument_nodes<'tree>(args: &Node<'tree>) -> Vec<Node<'tree>> {
    (0..args.child_count())
        .filter_map(|i| args.child(i))
        .filter(|child| child.is_named() && child.kind() != "comment")
        .collect()
}

/// The `(lower, higher)` argument-position pairs at which one call site hands
/// the callee two named, DIFFERENT storage objects.
///
/// Distinctness is per CALL SITE, not per position: one call passing `a` at
/// index 0 and another passing `b` at index 1 proves nothing, because no
/// single caller's path ever holds both.
pub fn distinct_object_pairs(
    frame: &ObjectFrame,
    args: &[Node],
    source: &str,
) -> Vec<(usize, usize)> {
    let bases: Vec<Option<String>> = args
        .iter()
        .map(|arg| frame.argument_object_base(arg, source))
        .collect();
    let mut pairs = Vec::new();
    for (left, left_base) in bases.iter().enumerate() {
        let Some(left_base) = left_base else { continue };
        for (right, right_base) in bases.iter().enumerate().skip(left + 1) {
            if right_base.as_ref().is_some_and(|base| base != left_base) {
                pairs.push((left, right));
            }
        }
    }
    pairs
}
