// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! What calling a function can change: a per-function mod/ref summary.
//!
//! Two halves. [`DirectEffects`] is what one body does by itself -- the
//! locations it writes, whether it reads a volatile object, and every call it
//! makes with what each argument designates -- collected per file during the
//! prescan and folded into the function's summary. [`EffectTable`] closes
//! those facts over the call graph of the whole scanned set, once per run,
//! so a caller inherits what its callees do, whichever file defines them.
//!
//! Library callees are recorded by name and judged when a consumer asks,
//! through the `stdlib_call_effects` contract, never baked into the table:
//! the environment axis decides what is known about the library (ADR-0015),
//! and a prescan cache must stay valid under every setting. How a consumer
//! treats a call nothing proves either way is its own policy.

use crate::analyze::macro_expand::{self, MacroArm};
use crate::utility::cert_c::ast_utils::{self, get_node_text, IdentifierBinding};
use std::collections::{BTreeSet, HashMap};
use tree_sitter::Node;

/// A location a function body may write.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Loc {
    /// An object with external linkage, by name, or a name this file never
    /// declares (a global declared in a header).
    Global(String),
    /// An object with static storage duration and internal linkage: a
    /// file-scope `static`, or a block-scope `static` local.
    Static(String),
    /// Whatever the function's parameter `k` (0-based) points to.
    ParamPointee(usize),
    /// Storage reached through a pointer that is not a parameter, or through
    /// a construct the collector cannot name.
    Unknown,
}

/// What a call argument designates, in the caller's frame.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum ArgRoot {
    /// The caller's own parameter `j`, passed on as is.
    Param(usize),
    /// The address of storage the caller owns and discards on return: `&x`
    /// of a non-static local, or a local array.
    AddrOfLocal,
    /// The address of a named object with static storage duration.
    AddrOfGlobal(String),
    /// Anything else.
    Other,
    /// A null pointer constant (`0`, `NULL`, `(void *)0`): nothing is
    /// written through it in a defined execution.
    Null,
}

/// One call in a body.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct CallSite {
    /// The callee as spelled, or `None` for a call through a pointer or a
    /// member (nothing names the body).
    pub callee: Option<String>,
    /// One root per argument, in order. Empty for a callee reached through a
    /// macro body, whose arguments are not separated.
    pub args: Vec<ArgRoot>,
    /// Per argument, the function a bare identifier argument names (one not
    /// declared as an object), so a header macro calling its parameter
    /// (`#define APPLY(fn, x) fn(x)`) resolves to it. Empty when no argument
    /// is one.
    #[serde(default)]
    pub arg_functions: Vec<Option<String>>,
    /// Per argument, the root its address would have (`&arg`): what a
    /// header macro assigning that parameter as a whole writes (an iterator
    /// macro stepping the caller's cursor). Empty when every argument's is
    /// [`ArgRoot::Other`].
    #[serde(default)]
    pub arg_objects: Vec<ArgRoot>,
}

/// One step of a member-access chain, from its root identifier outwards.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Step {
    /// `*e` or `e[i]`: one pointer level removed.
    Deref,
    /// `.f`, or `->f` (preceded by a [`Step::Deref`]).
    Field(String),
}

/// A member read whose type is only known once the project's struct tables
/// are, recorded as the root identifier's declared type and the steps from
/// it. A body cannot resolve it itself: the struct is usually defined in a
/// header, and the prescan reads each file on its own.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct MemberChain {
    /// The root identifier's declared type text.
    pub root_type: String,
    /// The steps from the root outwards.
    pub steps: Vec<Step>,
}

/// What one function body does by itself, before its callees are known.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectEffects {
    /// Locations the body writes, a function's own automatic objects never
    /// among them.
    pub writes: BTreeSet<Loc>,
    /// The body reads an object declared `volatile` (resolved to its
    /// declaration in this file).
    pub volatile_read: bool,
    /// Member reads that are volatile when the member's declared type is.
    pub member_chains: BTreeSet<MemberChain>,
    /// Every call, macro bodies this file defines already expanded into the
    /// callees they name.
    pub calls: BTreeSet<CallSite>,
    /// Inline assembly: anything may change.
    pub opaque: bool,
    /// Names the body reads that nothing in its file declares in scope: a
    /// header's global, an object-like macro, a constant, or something no
    /// scanned file declares. Judged against the project in the closure.
    #[serde(default)]
    pub free_names: BTreeSet<String>,
    /// Typedef names of the objects the body reads at the level the typedef
    /// qualifies (`reg_t *R; ... *R` reads a `reg_t`): volatile when the
    /// typedef is (`typedef volatile uint32_t reg_t;`), which the closure
    /// knows project-wide and a body usually does not.
    #[serde(default)]
    pub typedef_reads: BTreeSet<String>,
}

impl DirectEffects {
    /// Fold another definition of the same name in: `#if` alternatives or
    /// build-variant files, any of which may be the one compiled, so the
    /// union governs.
    pub fn merge(&mut self, other: DirectEffects) {
        self.writes.extend(other.writes);
        self.volatile_read |= other.volatile_read;
        self.member_chains.extend(other.member_chains);
        self.calls.extend(other.calls);
        self.opaque |= other.opaque;
        self.free_names.extend(other.free_names);
        self.typedef_reads.extend(other.typedef_reads);
    }
}

/// What resolving names in one file needs, found once per file: its
/// file-scope declarations by name, and the names any declaration in it
/// qualifies `volatile`.
///
/// `ast_utils::find_global_declaration_for_identifier` rescans the
/// translation unit's top level on every call, which is quadratic over a
/// large single-header library when asked for every name a body writes.
/// This index answers the same question -- the first direct-child
/// declaration binding the name -- from one pass.
pub struct FileScope<'t> {
    globals: HashMap<String, Node<'t>>,
    /// `None` when the file never spells `volatile`, so no identifier in it
    /// can read a volatile object it declares.
    volatile_names: Option<std::collections::HashSet<String>>,
}

impl<'t> FileScope<'t> {
    /// Index `root`, a translation unit.
    pub fn of(root: &Node<'t>, source: &str) -> Self {
        let mut globals = HashMap::new();
        for (name, decl) in file_scope_declarators(root, source) {
            globals.entry(name).or_insert(decl);
        }
        let volatile_names = source.contains("volatile").then(|| {
            lang_parsing_substrate::query::find_descendants(*root, |n| {
                matches!(n.kind(), "declaration" | "parameter_declaration")
            })
            .into_iter()
            .filter(|d| get_node_text(d, source).contains("volatile"))
            .flat_map(|d| declared_in(&d, source))
            .collect()
        });
        FileScope {
            globals,
            volatile_names,
        }
    }
}

/// Every `(name, declaration)` at file scope, in source order: the
/// translation unit's own declarations and those inside its top-level
/// `#if`/`#ifdef` blocks (a `static volatile int flag;` under `#ifdef` is as
/// file-scope as any), never a function body's.
fn file_scope_declarators<'t>(root: &Node<'t>, source: &str) -> Vec<(String, Node<'t>)> {
    let mut out = Vec::new();
    let mut stack = vec![*root];
    while let Some(scope) = stack.pop() {
        let mut cursor = scope.walk();
        let children: Vec<Node<'t>> = scope.children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            match child.kind() {
                "declaration" => {
                    let mut inner = child.walk();
                    for part in child.children(&mut inner) {
                        let declarator = match part.kind() {
                            "init_declarator" => {
                                part.child_by_field_name("declarator").unwrap_or(part)
                            }
                            "identifier"
                            | "pointer_declarator"
                            | "array_declarator"
                            | "function_declarator" => part,
                            _ => continue,
                        };
                        let name = ast_utils::get_identifier_from_declarator(&declarator, source);
                        if !name.is_empty() {
                            out.push((name, child));
                        }
                    }
                }
                k if k.starts_with("preproc_") => stack.push(child),
                _ => {}
            }
        }
    }
    // The stack visits a block after the declarations around it; source
    // order decides which declaration of a name answers.
    out.sort_by_key(|(_, d)| d.start_byte());
    out
}

/// What one file declares at file scope, `#if` blocks included, as
/// [`file_scope_objects`] reports it.
#[derive(Debug, Default)]
pub struct FileScopeObjects {
    /// Every object and enumeration constant. Functions are not objects.
    pub names: std::collections::HashSet<String>,
    /// The objects another file can read that are declared `volatile`.
    pub volatile: std::collections::HashSet<String>,
    /// The objects another file can read that some declaration here gives
    /// without `volatile`.
    pub non_volatile: std::collections::HashSet<String>,
}

/// The file-scope objects and enumeration constants `root` declares, and
/// which of the objects another file can read are `volatile`. A `static`
/// object has internal linkage, so another translation unit reading the
/// spelling reads a different object; it counts only when `shared` (a
/// header, whose statics every includer declares).
pub fn file_scope_objects(root: &Node, source: &str, shared: bool) -> FileScopeObjects {
    let mut out = FileScopeObjects::default();
    for (name, decl) in file_scope_declarators(root, source) {
        let Some(declarator) = ast_utils::declaration_declarator_for(&decl, &name, source) else {
            continue;
        };
        if declares_function(&declarator) {
            continue;
        }
        if shared || !ast_utils::declaration_has_storage_class(&decl, "static", source) {
            if ast_utils::declaration_has_qualifier(&decl, "volatile", source) {
                out.volatile.insert(name.clone());
            } else {
                out.non_volatile.insert(name.clone());
            }
        }
        out.names.insert(name);
    }
    // Enumeration constants are declared names too, whatever block their
    // `enum` is in, and whether or not a value is written.
    for e in lang_parsing_substrate::query::find_descendants_of_kind(*root, "enumerator") {
        if let Some(n) = e.child_by_field_name("name") {
            out.names.insert(get_node_text(&n, source).to_string());
        }
    }
    out
}

/// Collect `func`'s [`DirectEffects`]. `arms` is every function-like macro
/// definition in the file, every preprocessor branch
/// ([`macro_expand::collect_function_macro_arms`]); a call to one is judged
/// by what its bodies write and call.
pub fn collect_direct_effects(
    func: &Node,
    source: &str,
    arms: &HashMap<String, Vec<MacroArm>>,
    scope: &FileScope,
) -> DirectEffects {
    let mut collector = Collector {
        source,
        func: *func,
        root: crate::utility::cert_c::ast_utils::tree_root(func),
        params: crate::analyze::function_summary::collect_param_names(func, source),
        declared: declared_names(func, source),
        typed: typedef_declarations(func, source),
        arms,
        scope,
        out: DirectEffects::default(),
    };
    if let Some(body) = func.child_by_field_name("body") {
        collector.walk(&body);
    }
    collector.out
}

/// Every name `func` declares: its parameters and every declarator in its
/// body, whatever block it is in.
fn declared_names(func: &Node, source: &str) -> std::collections::HashSet<String> {
    lang_parsing_substrate::query::find_descendants(*func, |n| {
        matches!(n.kind(), "declaration" | "parameter_declaration")
    })
    .into_iter()
    .flat_map(|d| declared_in(&d, source))
    .collect()
}

/// The names a `declaration` or `parameter_declaration` introduces, an
/// initialized declarator (`int total = 0`) included.
fn declared_in(decl: &Node, source: &str) -> Vec<String> {
    let mut cursor = decl.walk();
    decl.children(&mut cursor)
        .map(|c| match c.kind() {
            "init_declarator" => c.child_by_field_name("declarator").unwrap_or(c),
            _ => c,
        })
        .map(|c| ast_utils::get_identifier_from_declarator(&c, source))
        .filter(|n| !n.is_empty())
        .collect()
}

/// The typedef name a declaration's type is, and the pointer/array levels of
/// its declarator for `name`: `reg_t *R` gives `("reg_t", 1)`.
fn typedef_declaration(decl: &Node, name: &str, source: &str) -> Option<(String, isize)> {
    let ty = decl.child_by_field_name("type")?;
    if ty.kind() != "type_identifier" {
        return None;
    }
    let mut d = ast_utils::declaration_declarator_for(decl, name, source)?;
    let mut levels = 0;
    while matches!(d.kind(), "pointer_declarator" | "array_declarator") {
        levels += 1;
        match d.child_by_field_name("declarator") {
            Some(inner) => d = inner,
            None => break,
        }
    }
    Some((get_node_text(&ty, source).to_string(), levels))
}

/// [`Collector::typed`]: the function's typedef-typed declarations by name.
fn typedef_declarations(func: &Node, source: &str) -> HashMap<String, Option<(String, isize)>> {
    let mut out: HashMap<String, Option<(String, isize)>> = HashMap::new();
    for decl in lang_parsing_substrate::query::find_descendants(*func, |n| {
        matches!(n.kind(), "declaration" | "parameter_declaration")
    }) {
        for name in declared_in(&decl, source) {
            let entry = typedef_declaration(&decl, &name, source);
            match out.get(&name) {
                Some(_) => {
                    out.insert(name, None);
                }
                None => {
                    if let Some(e) = entry {
                        out.insert(name, Some(e));
                    }
                }
            }
        }
    }
    out
}

/// C11 6.4.1 keywords, plus the GNU spellings of a few, which tree-sitter
/// can read as identifiers inside a macro argument it cannot parse.
const C_KEYWORDS: &[&str] = &[
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_Bool",
    "_Complex",
    "_Generic",
    "_Imaginary",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
    "__inline",
    "__inline__",
    "__restrict",
    "__volatile__",
    "__const",
    "__signed__",
    "__typeof__",
    "typeof",
    "__attribute__",
    "__extension__",
];

/// Where a name occurrence is bound.
enum Bound<'t> {
    Local(Node<'t>),
    Parameter,
    Global(Node<'t>),
}

struct Collector<'s, 't> {
    source: &'s str,
    func: Node<'t>,
    /// The root of `func`'s tree, which identifier lookups descend from.
    root: Node<'t>,
    params: Vec<String>,
    /// Every name the function declares: its parameters and every
    /// declarator in its body.
    declared: std::collections::HashSet<String>,
    /// The function's objects declared with a typedef name, by name: the
    /// typedef and the declarator's pointer/array levels. `None` for a name
    /// declared more than once in the function, which is resolved exactly.
    typed: HashMap<String, Option<(String, isize)>>,
    arms: &'s HashMap<String, Vec<MacroArm>>,
    scope: &'s FileScope<'t>,
    out: DirectEffects,
}

impl<'t> Collector<'_, 't> {
    fn walk(&mut self, root: &Node<'t>) {
        // Explicit stack: bodies nest as deep as their source does.
        let mut stack = vec![*root];
        while let Some(node) = stack.pop() {
            match node.kind() {
                // A function tree-sitter nested inside this one is a parse
                // artifact with its own summary.
                "function_definition" => continue,
                // A directive's names are read by the preprocessor, not the
                // program: skip an `#if`'s condition and an `#ifdef`'s name,
                // keep the arms, and skip `#define`s written in a body.
                "preproc_if" | "preproc_elif" | "preproc_ifdef" | "preproc_elifdef" => {
                    let skip = node
                        .child_by_field_name("condition")
                        .or_else(|| node.child_by_field_name("name"))
                        .map(|n| n.id());
                    let mut cursor = node.walk();
                    let children: Vec<Node> = node
                        .named_children(&mut cursor)
                        .filter(|c| Some(c.id()) != skip)
                        .collect();
                    stack.extend(children.into_iter().rev());
                    continue;
                }
                "preproc_def" | "preproc_function_def" | "preproc_call" | "preproc_defined" => {
                    continue
                }
                // Operands C11 leaves unevaluated (a VLA `sizeof` aside).
                "sizeof_expression" | "alignof_expression" | "string_literal" | "char_literal" => {
                    continue
                }
                "gnu_asm_expression" => {
                    self.out.opaque = true;
                    continue;
                }
                "assignment_expression" | "update_expression" => {
                    let target = node
                        .child_by_field_name("left")
                        .or_else(|| node.child_by_field_name("argument"));
                    match target {
                        Some(t) => {
                            if let Some(loc) = self.write_location(&t) {
                                self.out.writes.insert(loc);
                            }
                        }
                        None => {
                            self.out.writes.insert(Loc::Unknown);
                        }
                    }
                }
                "identifier" => {
                    if let Some(t) = self.typedef_read(&node) {
                        self.out.typedef_reads.insert(t);
                    }
                    if self.reads_volatile(&node) {
                        self.out.volatile_read = true;
                    } else if self.is_free(&node) {
                        self.out
                            .free_names
                            .insert(get_node_text(&node, self.source).to_string());
                    }
                }
                // `&p->f` takes the address; nothing is read.
                "field_expression" if dereferences_applied(&node, self.source) >= 0 => {
                    if let Some(chain) = self.member_chain(&node) {
                        self.out.member_chains.insert(chain);
                    }
                }
                "call_expression" => {
                    self.call(&node);
                    // `offsetof(type, member)` and `va_arg(ap, type)` name a
                    // type and a member; neither is read.
                    let callee = node
                        .child_by_field_name("function")
                        .map(|f| get_node_text(&f, self.source));
                    match callee {
                        Some("offsetof" | "__builtin_offsetof") => continue,
                        Some("va_arg" | "__builtin_va_arg") => {
                            let first = node
                                .child_by_field_name("arguments")
                                .and_then(|a| a.named_child(0));
                            stack.extend(first);
                            continue;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
            let mut cursor = node.walk();
            let children: Vec<Node> = node.named_children(&mut cursor).collect();
            stack.extend(children.into_iter().rev());
        }
    }

    fn call(&mut self, node: &Node<'t>) {
        let function = node.child_by_field_name("function");
        let callee = match function {
            Some(f) if f.kind() == "identifier" && !self.names_an_object(&f) => {
                Some(get_node_text(&f, self.source).to_string())
            }
            _ => None,
        };
        let arg_nodes: Vec<Node<'t>> = node
            .child_by_field_name("arguments")
            .map(|a| {
                let mut cursor = a.walk();
                a.named_children(&mut cursor)
                    .filter(|c| c.kind() != "comment")
                    .collect()
            })
            .unwrap_or_default();
        let (args, arg_functions): (Vec<ArgRoot>, Vec<Option<String>>) =
            arg_nodes.iter().map(|c| self.arg_root(c)).unzip();
        if let Some(name) = &callee {
            if let Some(arms) = self.arms.get(name).filter(|a| !a.is_empty()) {
                for arm in arms {
                    let body = macro_expand::macro_body_calls(arm);
                    if body.writes {
                        self.out.writes.insert(Loc::Unknown);
                    }
                    // Assigning a parameter writes what was passed there:
                    // nothing outside the frame for the caller's own local.
                    for &k in &body.written_params {
                        let written = match arg_nodes.get(k) {
                            Some(arg) => self.write_location(arg),
                            None => Some(Loc::Unknown),
                        };
                        self.out.writes.extend(written);
                    }
                    let reached = body
                        .callees
                        .iter()
                        .cloned()
                        .map(Some)
                        // A call through a parameter calls what is passed
                        // there; an argument that names no function, or a
                        // call through a member or a pointer, names no body.
                        .chain(
                            body.param_calls
                                .iter()
                                .map(|&k| arg_functions.get(k).cloned().flatten()),
                        )
                        // `(t)(x)`: a function passed there is called; a
                        // type is a cast; another expression is a call
                        // through it.
                        .chain(body.paren_param_calls.iter().filter_map(|&k| {
                            if let Some(f) = arg_functions.get(k).cloned().flatten() {
                                return Some(Some(f));
                            }
                            let arg = arg_nodes.get(k)?;
                            (!is_type_name_text(get_node_text(arg, self.source))).then_some(None)
                        }))
                        .chain(body.indirect.then_some(None));
                    let objects: Vec<ArgRoot> =
                        arg_nodes.iter().map(|a| self.object_root(a)).collect();
                    for callee in reached {
                        let site = callee
                            .as_deref()
                            .and_then(|c| forwarded_site(&body, c, &objects));
                        self.out.calls.insert(site.unwrap_or(CallSite {
                            callee,
                            ..Default::default()
                        }));
                    }
                }
                // The call itself stays too: an `#if` arm that does not
                // define the macro may leave the name a real function.
            }
        }
        let arg_functions = if arg_functions.iter().any(Option::is_some) {
            arg_functions
        } else {
            Vec::new()
        };
        let arg_objects: Vec<ArgRoot> = arg_nodes.iter().map(|a| self.object_root(a)).collect();
        let arg_objects = if arg_objects.iter().any(|r| *r != ArgRoot::Other) {
            arg_objects
        } else {
            Vec::new()
        };
        self.out.calls.insert(CallSite {
            callee,
            args,
            arg_functions,
            arg_objects,
        });
    }

    /// The root `&arg` would have: the caller's own storage, a named
    /// object, or storage a parameter points to.
    fn object_root(&self, arg: &Node<'t>) -> ArgRoot {
        match self.write_location(arg) {
            None => ArgRoot::AddrOfLocal,
            Some(Loc::Global(g) | Loc::Static(g)) => ArgRoot::AddrOfGlobal(g),
            Some(Loc::ParamPointee(j)) => ArgRoot::Param(j),
            Some(Loc::Unknown) => ArgRoot::Other,
        }
    }

    /// Where an assignment to `lvalue` lands; `None` for the function's own
    /// automatic storage (a parameter itself, a non-static local, an element
    /// or member of a local aggregate not reached through a pointer).
    fn write_location(&self, lvalue: &Node<'t>) -> Option<Loc> {
        match lvalue.kind() {
            "parenthesized_expression" => match lvalue.named_child(0) {
                Some(inner) => self.write_location(&inner),
                None => Some(Loc::Unknown),
            },
            "identifier" => self.named_location(lvalue, false),
            "subscript_expression" => {
                let base = lvalue.child_by_field_name("argument")?;
                if base.kind() == "identifier" {
                    if let Some(IdentifierBinding::Local(decl)) = self.binding(&base) {
                        if is_automatic_local_array(&decl, &base, self.source) {
                            return None;
                        }
                    }
                    // A named array with static storage, element written.
                    if let Some(loc @ (Loc::Global(_) | Loc::Static(_))) =
                        self.named_location(&base, true)
                    {
                        return Some(loc);
                    }
                }
                Some(self.pointee_location(&base))
            }
            "field_expression" => {
                let base = lvalue.child_by_field_name("argument")?;
                let through_pointer = lvalue
                    .child_by_field_name("operator")
                    .is_some_and(|op| get_node_text(&op, self.source) == "->");
                if through_pointer {
                    Some(self.pointee_location(&base))
                } else {
                    self.write_location(&base)
                }
            }
            "pointer_expression" => {
                let is_deref = lvalue
                    .child_by_field_name("operator")
                    .is_some_and(|op| get_node_text(&op, self.source) == "*");
                match lvalue.child_by_field_name("argument") {
                    Some(base) if is_deref => Some(self.pointee_location(&base)),
                    _ => Some(Loc::Unknown),
                }
            }
            _ => Some(Loc::Unknown),
        }
    }

    /// The object a named identifier designates. `element`: the name is
    /// indexed, so a parameter is a pointer to the caller's storage.
    fn named_location(&self, ident: &Node<'t>, element: bool) -> Option<Loc> {
        let name = get_node_text(ident, self.source);
        match self.binding(ident) {
            Some(IdentifierBinding::Parameter(_)) => {
                if element {
                    Some(self.param_pointee(name))
                } else {
                    None
                }
            }
            // A local declared under a preprocessor arm the use is not in
            // binds it in that configuration only; in the others the same
            // spelling names whatever declaration lies past the arm (`int g;
            // ... #ifdef LOCAL int g; #endif g = 1;`), so the write is that
            // object's. With nothing past the arm, a configuration without
            // it would not compile: the arm is active and its local is the
            // object (`#ifdef _WIN32 long n; #else int n; #endif n = 0;`),
            // and so it is when every alternative of the group declares it,
            // whatever lies past.
            Some(IdentifierBinding::Local(decl)) if in_other_arm(&decl, ident) => {
                if let Some(decls) = declarations_in_every_arm(&decl, name, self.source) {
                    return decls
                        .iter()
                        .find_map(|d| self.local_location(d, ident, name, element));
                }
                match self.binding_past_other_arms(ident) {
                    Some(IdentifierBinding::Local(outer)) => {
                        self.local_location(&outer, ident, name, element)
                    }
                    Some(IdentifierBinding::Parameter(_)) => {
                        element.then(|| self.param_pointee(name))
                    }
                    Some(IdentifierBinding::Global(outer)) => {
                        Some(global_location(&outer, name, self.source))
                    }
                    None => self.local_location(&decl, ident, name, element),
                }
            }
            Some(IdentifierBinding::Local(decl)) => {
                self.local_location(&decl, ident, name, element)
            }
            Some(IdentifierBinding::Global(decl)) => {
                Some(global_location(&decl, name, self.source))
            }
            None => Some(Loc::Global(name.to_string())),
        }
    }

    /// What a write to `ident`, bound by the local declaration `decl`,
    /// writes.
    fn local_location(
        &self,
        decl: &Node<'t>,
        ident: &Node<'t>,
        name: &str,
        element: bool,
    ) -> Option<Loc> {
        if ast_utils::declaration_has_storage_class(decl, "static", self.source) {
            Some(Loc::Static(name.to_string()))
        } else if ast_utils::declaration_has_storage_class(decl, "extern", self.source) {
            // `extern int hits;` in a block names the file-scope object.
            Some(Loc::Global(name.to_string()))
        } else if element && !is_automatic_local_array(decl, ident, self.source) {
            Some(Loc::Unknown)
        } else {
            None
        }
    }

    /// Where `ident` is bound once every local declaration in a
    /// preprocessor arm the use is not in is set aside: the enclosing
    /// blocks, then the parameters, then the file scope.
    fn binding_past_other_arms(&self, ident: &Node<'t>) -> Option<IdentifierBinding<'t>> {
        let name = get_node_text(ident, self.source);
        if let Some(decl) =
            ast_utils::find_enclosing_declaration_where(ident, name, self.source, &|d| {
                !in_other_arm(d, ident)
            })
        {
            return Some(IdentifierBinding::Local(decl));
        }
        if self.params.iter().any(|p| p == name)
            || ast_utils::find_parameter_declaration(&self.func, name, self.source).is_some()
        {
            return Some(IdentifierBinding::Parameter(String::new()));
        }
        self.scope
            .globals
            .get(name)
            .map(|d| IdentifierBinding::Global(*d))
    }

    /// What `*base` designates: parameter `k`'s pointee when `base` is that
    /// parameter, else storage nothing names.
    fn pointee_location(&self, base: &Node<'t>) -> Loc {
        let base = crate::analyze::init_state::strip_arg_casts(base);
        if base.kind() == "identifier" {
            if let Some(IdentifierBinding::Parameter(_)) = self.binding(&base) {
                return self.param_pointee(get_node_text(&base, self.source));
            }
        }
        Loc::Unknown
    }

    fn param_pointee(&self, name: &str) -> Loc {
        self.params
            .iter()
            .position(|p| p == name)
            .map_or(Loc::Unknown, Loc::ParamPointee)
    }

    /// Whether a callee identifier is declared as an object -- a parameter,
    /// a local or a file-scope function pointer -- rather than a function,
    /// so the call goes through a pointer and the spelling names no body
    /// (ADR-0006: a pointer parameter called `cmp` is not the scanned
    /// function `cmp`).
    fn names_an_object(&self, ident: &Node<'t>) -> bool {
        let name = get_node_text(ident, self.source);
        match self.binding(ident) {
            Some(IdentifierBinding::Parameter(_)) => true,
            Some(IdentifierBinding::Local(decl) | IdentifierBinding::Global(decl)) => {
                ast_utils::declaration_declarator_for(&decl, name, self.source)
                    .is_some_and(|d| !declares_function(&d))
            }
            None => false,
        }
    }

    /// Where `ident` is bound: the nearest enclosing local declaration, else
    /// this function's parameter, else the file-scope declaration -- the
    /// order `ast_utils::resolve_identifier_binding` resolves in, with the
    /// file scope read from the index.
    fn bound(&self, ident: &Node<'t>) -> Option<Bound<'t>> {
        let name = get_node_text(ident, self.source);
        // The scope chain from one descent of the tree, not a `parent()`
        // climb per scope: a function with a long else-if chain is as deep
        // as it is long. From the root, not the function, so a function
        // nested in a block still sees that block's earlier declarations,
        // as the climb does.
        if let Some(decl) = ast_utils::find_enclosing_declaration_for_identifier_in(
            &self.root,
            ident,
            name,
            self.source,
        ) {
            return Some(Bound::Local(decl));
        }
        // `collect_param_names` leaves a function-pointer parameter
        // (`void (*cb)(void)`) unnamed, so ask the declaration too.
        if self.params.iter().any(|p| p == name)
            || ast_utils::find_parameter_declaration(&self.func, name, self.source).is_some()
        {
            return Some(Bound::Parameter);
        }
        self.scope.globals.get(name).map(|d| Bound::Global(*d))
    }

    fn binding(&self, ident: &Node<'t>) -> Option<IdentifierBinding<'t>> {
        Some(match self.bound(ident)? {
            Bound::Local(d) => IdentifierBinding::Local(d),
            Bound::Parameter => IdentifierBinding::Parameter(String::new()),
            Bound::Global(d) => IdentifierBinding::Global(d),
        })
    }

    /// The declaring node and the declarator binding `ident`.
    fn declarator(&self, ident: &Node<'t>) -> Option<(Node<'t>, Node<'t>)> {
        let name = get_node_text(ident, self.source);
        let decl = match self.bound(ident)? {
            Bound::Local(d) | Bound::Global(d) => d,
            Bound::Parameter => {
                ast_utils::find_parameter_declaration(&self.func, name, self.source)?
            }
        };
        let declarator = ast_utils::declaration_declarator_for(&decl, name, self.source)?;
        Some((decl, declarator))
    }

    /// The typedef an identifier read reads an object of, when the read
    /// reaches the level the typedef names (`*R` for `reg_t *R`, `v` for
    /// `reg_t v`).
    fn typedef_read(&self, ident: &Node<'t>) -> Option<String> {
        let name = get_node_text(ident, self.source);
        let (ty, levels) = match self.typed.get(name) {
            Some(Some(entry)) => entry.clone(),
            // Declared twice in the function: resolve this occurrence.
            Some(None) => {
                let (decl, _) = self.declarator(ident)?;
                typedef_declaration(&decl, name, self.source)?
            }
            None if self.declared.contains(name) => return None,
            None => {
                let decl = self.scope.globals.get(name)?;
                typedef_declaration(decl, name, self.source)?
            }
        };
        typedef_level(&ty, dereferences_applied(ident, self.source) - levels)
    }

    /// Whether an identifier read names something neither the function nor
    /// its file declares: a header's object, a macro, a constant, or
    /// something unknown. A callee is judged as a call, not here.
    fn is_free(&self, ident: &Node<'t>) -> bool {
        let name = get_node_text(ident, self.source);
        // A keyword read as an identifier is a misparse around a macro
        // argument (`list_first(&l, struct node, link)`), not a name.
        if C_KEYWORDS.contains(&name) {
            return false;
        }
        let is_callee = ident.parent().is_some_and(|p| {
            p.kind() == "call_expression"
                && p.child_by_field_name("function")
                    .is_some_and(|f| f.id() == ident.id())
        });
        !is_callee && !self.declared.contains(name) && !self.scope.globals.contains_key(name)
    }

    /// [`is_volatile_read`], answered only for names some declaration in
    /// the file qualifies `volatile`.
    fn reads_volatile(&self, ident: &Node<'t>) -> bool {
        let Some(names) = &self.scope.volatile_names else {
            return false;
        };
        if !names.contains(get_node_text(ident, self.source)) {
            return false;
        }
        self.declarator(ident).is_some_and(|(decl, declarator)| {
            volatile_read_of(ident, &decl, &declarator, self.source)
        })
    }

    /// [`member_chain`], with the root resolved through the index.
    fn member_chain(&self, node: &Node<'t>) -> Option<MemberChain> {
        member_chain_with(node, self.source, &|ident| {
            let (decl, declarator) = self.declarator(ident)?;
            declared_type(&decl, &declarator, self.source)
        })
    }

    /// What an argument designates, and the function it names when it is a
    /// bare identifier not declared as an object.
    fn arg_root(&self, arg: &Node<'t>) -> (ArgRoot, Option<String>) {
        let arg = crate::analyze::init_state::strip_arg_casts(arg);
        if is_null_pointer_constant(&arg, self.source) {
            return (ArgRoot::Null, None);
        }
        match arg.kind() {
            "identifier" => {
                let name = get_node_text(&arg, self.source);
                match self.binding(&arg) {
                    Some(IdentifierBinding::Parameter(_)) => (
                        self.params
                            .iter()
                            .position(|p| p == name)
                            .map_or(ArgRoot::Other, ArgRoot::Param),
                        None,
                    ),
                    // A local array decays to its own storage's address.
                    Some(IdentifierBinding::Local(decl))
                        if is_automatic_local_array(&decl, &arg, self.source) =>
                    {
                        (ArgRoot::AddrOfLocal, None)
                    }
                    Some(IdentifierBinding::Local(decl) | IdentifierBinding::Global(decl))
                        if ast_utils::declaration_declarator_for(&decl, name, self.source)
                            .is_some_and(|d| !declares_function(&d)) =>
                    {
                        (ArgRoot::Other, None)
                    }
                    _ => (ArgRoot::Other, Some(name.to_string())),
                }
            }
            "pointer_expression"
                if arg
                    .child_by_field_name("operator")
                    .is_some_and(|op| get_node_text(&op, self.source) == "&") =>
            {
                // `&p[i]`, `&p->f`: inside what parameter `j` points to.
                match arg.child_by_field_name("argument") {
                    Some(operand) => (self.object_root(&operand), None),
                    None => (ArgRoot::Other, None),
                }
            }
            _ => (ArgRoot::Other, None),
        }
    }
}

/// Whether an argument is a null pointer constant (C11 6.3.2.3p3), casts
/// aside: `NULL` or `nullptr` unless a declaration in scope binds the name,
/// or an integer constant `0` in any spelling.
pub fn is_null_pointer_constant(arg: &Node, source: &str) -> bool {
    let arg = crate::analyze::init_state::strip_arg_casts(arg);
    match arg.kind() {
        "null" => true,
        "identifier" => {
            let name = get_node_text(&arg, source);
            name == "NULL" && ast_utils::resolve_identifier_binding(&arg, name, source).is_none()
        }
        "number_literal" => {
            let digits = get_node_text(&arg, source).trim_end_matches(['u', 'U', 'l', 'L']);
            let digits = digits
                .strip_prefix("0x")
                .or_else(|| digits.strip_prefix("0X"))
                .unwrap_or(digits);
            !digits.is_empty() && digits.chars().all(|c| c == '0')
        }
        _ => false,
    }
}

/// What a write to the file-scope object `name`, declared by `decl`,
/// writes.
fn global_location(decl: &Node, name: &str, source: &str) -> Loc {
    if ast_utils::declaration_has_storage_class(decl, "static", source) {
        Loc::Static(name.to_string())
    } else {
        Loc::Global(name.to_string())
    }
}

/// The declarations of `name` in every alternative of the `#if` group
/// holding `decl`, when each declares it directly and the group ends in an
/// `#else`: then one of them binds the name in every configuration. `None`
/// when some configuration may leave it undeclared.
fn declarations_in_every_arm<'t>(
    decl: &Node<'t>,
    name: &str,
    source: &str,
) -> Option<Vec<Node<'t>>> {
    let mut head = decl.parent()?;
    while matches!(
        head.kind(),
        "preproc_else" | "preproc_elif" | "preproc_elifdef"
    ) {
        head = head.parent()?;
    }
    if !matches!(head.kind(), "preproc_if" | "preproc_ifdef") {
        return None;
    }
    let mut found = Vec::new();
    let mut arm = Some(head);
    while let Some(current) = arm {
        let mut cursor = current.walk();
        let declared = current.named_children(&mut cursor).find(|d| {
            d.kind() == "declaration" && declared_in(d, source).iter().any(|n| n == name)
        })?;
        found.push(declared);
        if current.kind() == "preproc_else" {
            return Some(found);
        }
        arm = current.child_by_field_name("alternative");
    }
    None
}

/// Whether `decl` sits in a preprocessor arm that does not also hold `usage`:
/// under an `#if` whose block `usage` is outside, or in the `#else`/`#elif`
/// alternative of one whose other branch holds `usage` (or the reverse).
fn in_other_arm(decl: &Node, usage: &Node) -> bool {
    let within = |outer: &Node, inner: &Node| {
        outer.start_byte() <= inner.start_byte() && inner.end_byte() <= outer.end_byte()
    };
    let mut node = decl.parent();
    while let Some(ancestor) = node {
        if ancestor.kind() == "function_definition" {
            return false;
        }
        if matches!(
            ancestor.kind(),
            "preproc_if" | "preproc_ifdef" | "preproc_elif" | "preproc_elifdef"
        ) {
            if !within(&ancestor, usage) {
                return true;
            }
            if let Some(alternative) = ancestor.child_by_field_name("alternative") {
                if within(&alternative, usage) != within(&alternative, decl) {
                    return true;
                }
            }
        }
        node = ancestor.parent();
    }
    false
}

/// Whether a declarator declares a function (`f(void)`, `*f(void)`) rather
/// than an object, a function pointer (`(*fp)(void)`) included.
fn declares_function(declarator: &Node) -> bool {
    let mut d = *declarator;
    loop {
        match d.kind() {
            "function_declarator" => {
                return d
                    .child_by_field_name("declarator")
                    .is_some_and(|inner| inner.kind() == "identifier");
            }
            "pointer_declarator" => match d.child_by_field_name("declarator") {
                Some(inner) => d = inner,
                None => return false,
            },
            _ => return false,
        }
    }
}

/// Whether `decl` (a block-scope declaration binding `ident`) declares an
/// array with automatic storage (neither `static` nor `extern`): storage the
/// function owns.
fn is_automatic_local_array(decl: &Node, ident: &Node, source: &str) -> bool {
    !ast_utils::declaration_has_storage_class(decl, "static", source)
        && !ast_utils::declaration_has_storage_class(decl, "extern", source)
        && ast_utils::declaration_declarator_for(decl, get_node_text(ident, source), source)
            .is_some_and(|d| d.kind() == "array_declarator")
}

/// Whether a callee identifier is declared as an object -- a parameter, a
/// local or a file-scope function pointer -- so the call goes through a
/// pointer and the spelling names no function (ADR-0006: a parameter called
/// `next` is not another file's function `next`).
pub fn designates_object(ident: &Node, source: &str) -> bool {
    let name = get_node_text(ident, source);
    match ast_utils::resolve_identifier_binding(ident, name, source) {
        Some(IdentifierBinding::Parameter(_)) => true,
        Some(IdentifierBinding::Local(decl) | IdentifierBinding::Global(decl)) => {
            ast_utils::declaration_declarator_for(&decl, name, source)
                .is_some_and(|d| !declares_function(&d))
        }
        None => false,
    }
}

/// Whether an identifier occurrence reads a volatile object, resolved to its
/// declaration (ADR-0006), never matched by spelling. A declaration's own
/// `volatile` qualifies what its pointers and arrays finally reach, so
/// `volatile T *p` makes `*p`, `p->f` and `p[i]` volatile reads and `p`
/// itself not; `T *volatile p` makes `p` one.
pub fn is_volatile_read(ident: &Node, source: &str) -> bool {
    let name = get_node_text(ident, source);
    ast_utils::resolve_identifier_declarator(ident, name, source)
        .is_some_and(|(decl, declarator)| volatile_read_of(ident, &decl, &declarator, source))
}

/// [`is_volatile_read`] once the declaration is known.
fn volatile_read_of(ident: &Node, decl: &Node, declarator: &Node, source: &str) -> bool {
    let mut levels = 0;
    let mut own_qualifier = false;
    let mut node = Some(*declarator);
    while let Some(d) = node {
        match d.kind() {
            "pointer_declarator" | "array_declarator" => {
                levels += 1;
                let inner = d.child_by_field_name("declarator");
                if d.kind() == "pointer_declarator"
                    && inner.is_some_and(|i| i.kind() == "identifier")
                    && ast_utils::declaration_has_qualifier(&d, "volatile", source)
                {
                    own_qualifier = true;
                }
                node = inner;
            }
            _ => node = None,
        }
    }
    let derefs = dereferences_applied(ident, source);
    // `&x` takes the address; nothing is read.
    derefs >= 0
        && (own_qualifier
            || (ast_utils::declaration_has_qualifier(decl, "volatile", source)
                && derefs >= levels as isize))
}

/// The declared type text of a declarator, as
/// `ast_utils::resolve_identifier_declared_type` spells it.
fn declared_type(decl: &Node, declarator: &Node, source: &str) -> Option<String> {
    let base = get_node_text(&decl.child_by_field_name("type")?, source)
        .trim()
        .to_string();
    if base.is_empty() {
        return None;
    }
    let mut d = *declarator;
    let mut pointer_like = false;
    loop {
        match d.kind() {
            "pointer_declarator" | "array_declarator" => pointer_like = true,
            "function_declarator" => return None,
            "parenthesized_declarator" => {}
            _ => break,
        }
        match d.child_by_field_name("declarator") {
            Some(inner) => d = inner,
            None => break,
        }
    }
    Some(if pointer_like {
        format!("{} *", base)
    } else {
        base
    })
}

/// How many dereferences the expression around a node applies to it:
/// `*p`, `p[i]` and `p->f` one each, `&x` minus one. Negative when only the
/// address is taken.
pub fn dereferences_applied(node: &Node, source: &str) -> isize {
    let mut depth: isize = 0;
    let mut child = *node;
    while let Some(parent) = child.parent() {
        let is_operand = parent
            .child_by_field_name("argument")
            .is_some_and(|a| a.id() == child.id());
        match parent.kind() {
            "parenthesized_expression" => {}
            "pointer_expression" if is_operand => {
                match parent
                    .child_by_field_name("operator")
                    .map(|o| get_node_text(&o, source))
                {
                    Some("*") => depth += 1,
                    Some("&") => depth -= 1,
                    _ => break,
                }
            }
            "subscript_expression" if is_operand => depth += 1,
            "field_expression" if is_operand => {
                if parent
                    .child_by_field_name("operator")
                    .is_some_and(|o| get_node_text(&o, source) == "->")
                {
                    depth += 1;
                }
            }
            _ => break,
        }
        child = parent;
    }
    depth
}

/// The chain from a member access back to the identifier it starts at, with
/// that identifier's declared type (ADR-0006). `None` when the chain starts
/// anywhere else (a call's result, a literal) or the root is undeclared here.
pub fn member_chain(node: &Node, source: &str) -> Option<MemberChain> {
    member_chain_with(node, source, &|ident| {
        ast_utils::resolve_identifier_declared_type(ident, get_node_text(ident, source), source)
    })
}

fn member_chain_with<'t>(
    node: &Node<'t>,
    source: &str,
    root_type: &dyn Fn(&Node<'t>) -> Option<String>,
) -> Option<MemberChain> {
    let mut steps = Vec::new();
    let mut n = *node;
    loop {
        match n.kind() {
            "identifier" => {
                let root_type = root_type(&n)?;
                steps.reverse();
                return Some(MemberChain { root_type, steps });
            }
            "parenthesized_expression" => n = n.named_child(0)?,
            "pointer_expression" | "subscript_expression" => {
                if n.kind() == "pointer_expression"
                    && n.child_by_field_name("operator")
                        .is_none_or(|o| get_node_text(&o, source) != "*")
                {
                    return None;
                }
                steps.push(Step::Deref);
                n = n.child_by_field_name("argument")?;
            }
            "field_expression" => {
                steps.push(Step::Field(
                    get_node_text(&n.child_by_field_name("field")?, source).to_string(),
                ));
                // Pushed after the field: reversed, `->f` reads Deref, Field.
                if n.child_by_field_name("operator")
                    .is_some_and(|o| get_node_text(&o, source) == "->")
                {
                    steps.push(Step::Deref);
                }
                n = n.child_by_field_name("argument")?;
            }
            _ => return None,
        }
    }
}

/// Compiler builtins that compute a value and change nothing (GCC manual,
/// "Other Built-in Functions"): `likely(x)` is not an unknown call.
pub const PURE_BUILTINS: &[&str] = &[
    "__builtin_expect",
    "__builtin_expect_with_probability",
    "__builtin_constant_p",
    "__builtin_types_compatible_p",
    "__builtin_choose_expr",
    "__builtin_offsetof",
    "__builtin_object_size",
    "__builtin_dynamic_object_size",
];

/// Callees that change nothing the program goes on with: an assertion
/// evaluates its condition (judged where it is written) or aborts.
/// Whether `name` names a type rather than a function: a type name
/// [`is_type_name_text`] recognises, a typedef the scan knows, or an ISO
/// C/POSIX `_t` name (POSIX reserves the suffix for types). A "call" of one
/// in a macro body is a cast (`#define CAST(T, x) (T)(x)`), which evaluates
/// nothing.
pub fn names_a_type(name: &str, typedefs: &HashMap<String, String>) -> bool {
    is_type_name_text(name) || typedefs.contains_key(name) || name.ends_with("_t")
}

/// Whether a macro argument's text is a type name by its spelling alone:
/// it ends in `*` (`union GCUnion *`, which no expression does), starts with
/// `struct`/`union`/`enum`, or is only type keywords and qualifiers
/// (`unsigned long`, `const char`).
pub fn is_type_name_text(text: &str) -> bool {
    let text = text.trim();
    if text.is_empty() {
        return false;
    }
    if text.ends_with('*') {
        return true;
    }
    let words: Vec<&str> = text.split_whitespace().collect();
    if matches!(words.first(), Some(&("struct" | "union" | "enum"))) {
        return true;
    }
    words.iter().all(|w| {
        matches!(
            *w,
            "char"
                | "short"
                | "int"
                | "long"
                | "float"
                | "double"
                | "void"
                | "signed"
                | "unsigned"
                | "_Bool"
                | "_Complex"
                | "bool"
                | "const"
                | "volatile"
                | "restrict"
                | "_Atomic"
        )
    })
}

fn is_effect_free_builtin(name: &str) -> bool {
    matches!(name, "assert" | "static_assert" | "_Static_assert") || PURE_BUILTINS.contains(&name)
}

/// What calling a function can change, its callees' effects included.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClosedEffects {
    /// Program locations written, in this function's own frame: a callee's
    /// write through its parameter is mapped through the argument passed
    /// (the caller's own parameter, a local's address -- dropped -- or a
    /// global's), anything else to [`Loc::Unknown`].
    pub writes: BTreeSet<Loc>,
    /// Some write happens: one in [`Self::writes`], or one that lands in
    /// the storage of a function on the call path ([`Self::frame_write`]).
    /// The conservative reading, in which a callee that writes through a
    /// pointer it was handed counts even when the caller handed it a local.
    /// A write through a null pointer argument is not one: it does not
    /// happen in a defined execution.
    pub writes_any: bool,
    /// Some callee writes through a pointer to a local of a function on the
    /// call path (`int v; fill(&v);`), which no caller of that function
    /// sees.
    pub frame_write: bool,
    /// A volatile object is read.
    pub volatile_read: bool,
    /// A library callee whose contract has a side effect is reached.
    pub lib_side_effect: bool,
    /// A library callee whose only effect is its own returned static buffer
    /// is reached.
    pub lib_own_buffer: bool,
    /// Any ISO C or POSIX library callee is reached, pure ones included.
    pub lib_any: bool,
    /// Something nothing summarizes is reached: a call through a pointer,
    /// inline assembly, a name no scanned file defines and no library list
    /// knows, or a macro with no readable body.
    pub opaque: bool,
}

/// A function's effect as one consumer's settings see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proof {
    /// Shown to change nothing.
    Pure,
    /// Neither shown pure nor shown impure: the consumer's own policy
    /// decides.
    Unproven,
    /// Shown to change program state.
    Impure,
}

impl ClosedEffects {
    /// The verdict. A write is proven only when it lands outside this
    /// function's own frame ([`Self::writes`]); one that lands only in its
    /// own storage (`int v; fill(&v);`) is [`Self::writes_any`] alone and
    /// unproven, left to the consumer's policy. `stdlib_contract` is the
    /// `stdlib_call_effects` environment contract: withdrawn, a library
    /// callee is as unknown as any other body-less one.
    pub fn proof(&self, stdlib_contract: bool) -> Proof {
        if !self.writes.is_empty()
            || self.volatile_read
            || (stdlib_contract && self.lib_side_effect)
        {
            Proof::Impure
        } else if self.writes_any
            || self.opaque
            || (stdlib_contract && self.lib_own_buffer)
            || (!stdlib_contract && self.lib_any)
        {
            Proof::Unproven
        } else {
            Proof::Pure
        }
    }

    /// These effects for one call whose argument `k` is a null pointer
    /// constant wherever `null(k)`: a write through that parameter does not
    /// happen in a defined execution.
    pub fn past_null_arguments(&self, null: impl Fn(usize) -> bool) -> ClosedEffects {
        let mut out = self.clone();
        out.writes
            .retain(|loc| !matches!(loc, Loc::ParamPointee(k) if null(*k)));
        out.writes_any = !out.writes.is_empty() || out.frame_write;
        out
    }

    /// Everything either may change: the worse of two definitions.
    pub fn union(&self, other: &ClosedEffects) -> ClosedEffects {
        let mut out = self.clone();
        out.absorb_flags(other);
        out.writes_any |= other.writes_any;
        out.writes.extend(other.writes.iter().cloned());
        out
    }

    /// The flags a caller inherits whatever it passes. `writes_any` is not
    /// among them: a callee's writes reach the caller only as mapped
    /// through its arguments.
    fn absorb_flags(&mut self, other: &ClosedEffects) {
        self.frame_write |= other.frame_write;
        self.volatile_read |= other.volatile_read;
        self.lib_side_effect |= other.lib_side_effect;
        self.lib_own_buffer |= other.lib_own_buffer;
        self.lib_any |= other.lib_any;
        self.opaque |= other.opaque;
    }
}

/// What the project knows about names a body reads without declaring them.
#[derive(Debug, Clone, Default)]
pub struct ProjectNames {
    /// Every `#define`, every arm (object-like bodies are expanded).
    pub macro_definitions:
        std::sync::Arc<HashMap<String, Vec<crate::analyze::check_macros::MacroDefinition>>>,
    /// File-scope objects some file or header declares `volatile`.
    pub volatile_globals: std::sync::Arc<std::collections::HashSet<String>>,
    /// File-scope objects some file or header declares without `volatile`.
    pub non_volatile_globals: std::sync::Arc<std::collections::HashSet<String>>,
    /// Every file-scope object name declared anywhere in the scan.
    pub global_objects: std::sync::Arc<std::collections::HashSet<String>>,
    /// Every function name defined or declared in the scan.
    pub functions: std::sync::Arc<std::collections::HashSet<String>>,
    /// Numeric macro and enumeration constants.
    pub constants: std::sync::Arc<HashMap<String, i64>>,
    /// Every macro name defined anywhere in the scan.
    pub macros: std::sync::Arc<std::collections::HashSet<String>>,
    /// Typedef names (a macro argument may name a type).
    pub typedefs: std::sync::Arc<HashMap<String, String>>,
    /// Every struct or union member name (a macro argument may name one).
    pub members: std::sync::Arc<std::collections::HashSet<String>>,
    /// Typedef names whose definition carries `volatile`
    /// (`typedef volatile uint32_t reg_t;`).
    pub volatile_typedefs: std::sync::Arc<std::collections::HashSet<String>>,
    /// Whether these tables describe a prescan. Without one, a name nothing
    /// here knows is not evidence of anything, so it is not judged unknown.
    pub complete: bool,
}

/// The project tables the closure resolves callees and member types against.
pub struct EffectInputs<'a> {
    /// Names read without a declaration in scope.
    pub names: &'a ProjectNames,
    /// One definition per function-like macro name, project-wide.
    pub function_macros: &'a HashMap<String, macro_expand::FunctionMacro>,
    /// Every definition of every function-like macro the scanned headers
    /// give, each `#if` alternative its own
    /// (`ProjectContext::function_macro_arms`).
    pub function_macro_arms: &'a HashMap<String, Vec<macro_expand::ProjectMacroArm>>,
    /// Every function-like macro name: what makes a call a macro invocation.
    pub function_macro_names: &'a std::collections::HashSet<String>,
    /// Object-like aliases (`#define ASSERT assert`).
    pub macro_aliases: &'a HashMap<String, String>,
    /// `struct tag -> field -> type text`.
    pub struct_field_types: &'a HashMap<String, HashMap<String, String>>,
    /// `typedef name -> aliased type text`.
    pub typedef_types: &'a HashMap<String, String>,
}

/// [`ClosedEffects`] for every function the scan defines, keyed as the
/// function summaries are (a bare name, or a file-qualified one for a
/// `static` several files define).
#[derive(Debug, Default)]
pub struct EffectTable {
    by_key: HashMap<String, ClosedEffects>,
}

impl EffectTable {
    /// The effects of the function stored under `key`.
    pub fn get(&self, key: &str) -> Option<&ClosedEffects> {
        self.by_key.get(key)
    }

    /// Close every function's [`DirectEffects`] over the call graph.
    /// Mutually recursive functions share every flag (each reaches all the
    /// others); their mapped write sets are iterated to a fixpoint within
    /// the group. Iterative Tarjan: call chains are as deep as the code.
    pub fn build<'d>(
        functions: impl Iterator<Item = (String, &'d DirectEffects)>,
        inputs: &EffectInputs,
    ) -> Self {
        Self::build_over(functions, inputs, &|_| None)
    }

    /// [`Self::build`] for functions a finished table does not hold -- the
    /// file under check, when the prescan did not read it (a run whose `-d`
    /// names only the include directories). A callee none of `functions`
    /// defines is looked up in `base` before the library lists, and its
    /// closed effects are taken as they are.
    pub fn build_over<'d>(
        functions: impl Iterator<Item = (String, &'d DirectEffects)>,
        inputs: &EffectInputs,
        base: &dyn Fn(&str) -> Option<ClosedEffects>,
    ) -> Self {
        let functions: Vec<(String, &DirectEffects)> = functions.collect();
        let index: HashMap<&str, usize> = functions
            .iter()
            .enumerate()
            .map(|(i, (k, _))| (k.as_str(), i))
            .collect();

        // Each function's own facts, and its edges to other functions.
        let mut local: Vec<ClosedEffects> = Vec::with_capacity(functions.len());
        let mut edges: Vec<Vec<(usize, Vec<ArgRoot>)>> = Vec::with_capacity(functions.len());
        for (_, direct) in &functions {
            let mut own = ClosedEffects {
                writes: direct.writes.clone(),
                writes_any: !direct.writes.is_empty(),
                volatile_read: direct.volatile_read
                    || direct
                        .member_chains
                        .iter()
                        .any(|c| chain_is_volatile(c, inputs)),
                opaque: direct.opaque,
                ..Default::default()
            };
            let mut out = Vec::new();
            let mut resolver = Resolver {
                lenient: false,
                inputs,
                index: &index,
                base,
                own: &mut own,
                out: &mut out,
            };
            for call in &direct.calls {
                match &call.callee {
                    Some(name) => resolver.classify(name, call, 0),
                    None => resolver.own.opaque = true,
                }
            }
            for name in &direct.free_names {
                resolver.free_name(name, 0);
            }
            if direct
                .typedef_reads
                .iter()
                .any(|t| typedef_is_volatile(t, inputs.names))
            {
                resolver.own.volatile_read = true;
            }
            local.push(own);
            edges.push(out);
        }

        let n = functions.len();
        let mut closed: Vec<Option<ClosedEffects>> = vec![None; n];
        for scc in tarjan_sccs(n, &edges) {
            let in_scc: std::collections::HashSet<usize> = scc.iter().copied().collect();
            // Flags: shared by the whole group.
            let mut flags = ClosedEffects::default();
            for &m in &scc {
                flags.absorb_flags(&local[m]);
                for (t, _) in &edges[m] {
                    if !in_scc.contains(t) {
                        if let Some(c) = &closed[*t] {
                            flags.absorb_flags(c);
                        }
                    }
                }
            }
            // Mapped writes: to a fixpoint within the group. Each pass only
            // adds, and every location is a parameter pointee, a name some
            // body spells or `Unknown`, so the sets are bounded and this ends.
            let mut writes: HashMap<usize, BTreeSet<Loc>> =
                scc.iter().map(|&m| (m, local[m].writes.clone())).collect();
            loop {
                let mut changed = false;
                for &m in &scc {
                    let mut add = BTreeSet::new();
                    for (t, args) in &edges[m] {
                        let callee_writes = if in_scc.contains(t) {
                            writes.get(t)
                        } else {
                            closed[*t].as_ref().map(|c| &c.writes)
                        };
                        for loc in callee_writes.into_iter().flatten() {
                            match map_through(loc, args) {
                                Mapped::To(loc) => {
                                    add.insert(loc);
                                }
                                Mapped::CallerFrame => flags.frame_write = true,
                                Mapped::Nowhere => {}
                            }
                        }
                    }
                    let own = writes.get_mut(&m).expect("member");
                    for loc in add {
                        changed |= own.insert(loc);
                    }
                }
                if !changed {
                    break;
                }
            }
            for &m in &scc {
                let mut result = flags.clone();
                result.writes = writes.remove(&m).unwrap_or_default();
                result.writes_any = !result.writes.is_empty() || result.frame_write;
                closed[m] = Some(result);
            }
        }

        EffectTable {
            by_key: functions
                .into_iter()
                .zip(closed)
                .map(|((k, _), c)| (k, c.unwrap_or_default()))
                .collect(),
        }
    }
}

/// Whether a typedef read (as [`typedef_read`] spells it: the name, then
/// one `*` per dereference past it) reads a volatile-qualified object: the
/// typedef's own definition is volatile at that level, or it aliases,
/// through `typedefs`, one that is.
pub fn typedef_is_volatile(read: &str, names: &ProjectNames) -> bool {
    let base = read.trim_end_matches('*');
    let past = &read[base.len()..];
    let mut current = base;
    for _ in 0..8 {
        if names
            .volatile_typedefs
            .contains(&format!("{current}{past}"))
        {
            return true;
        }
        match names.typedefs.get(current) {
            Some(next) => current = next.as_str(),
            None => return false,
        }
    }
    false
}

/// The typedef names `root` defines with `volatile` in their type, `#if`
/// blocks included, each spelled at the level the volatile object lies: the
/// name for `typedef volatile uint32_t reg_t;`, and `vptr*` for `typedef
/// volatile int *vptr;`, whose pointer is not volatile but whose pointee is.
pub fn volatile_typedefs(root: &Node, source: &str) -> std::collections::HashSet<String> {
    lang_parsing_substrate::query::find_descendants(*root, |n| n.kind() == "type_definition")
        .into_iter()
        .filter(|def| {
            let mut cursor = def.walk();
            let qualified = def
                .children(&mut cursor)
                .any(|c| c.kind() == "type_qualifier" && get_node_text(&c, source) == "volatile");
            qualified
        })
        .flat_map(|def| {
            let mut cursor = def.walk();
            def.children_by_field_name("declarator", &mut cursor)
                .filter_map(|d| {
                    let mut d = d;
                    let mut levels = 0;
                    while d.kind() == "pointer_declarator" {
                        levels += 1;
                        d = d.child_by_field_name("declarator")?;
                    }
                    (d.kind() == "type_identifier")
                        .then(|| format!("{}{}", get_node_text(&d, source), "*".repeat(levels)))
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The typedef an identifier read reads an object of, from the level the
/// typedef names on, resolved to its declaration (ADR-0006): the name, then
/// one `*` per dereference past that level. For a rule judging an expression
/// it has in hand.
pub fn typedef_read(ident: &Node, source: &str) -> Option<String> {
    let name = get_node_text(ident, source);
    let (decl, _) = ast_utils::resolve_identifier_declarator(ident, name, source)?;
    let (ty, levels) = typedef_declaration(&decl, name, source)?;
    typedef_level(&ty, dereferences_applied(ident, source) - levels)
}

/// A read `past` dereferences into typedef `ty`, spelled as the typedef
/// name followed by one `*` per dereference (`vptr*` for `*P` given `vptr
/// P`); `None` when the read stops short of the level the typedef names.
fn typedef_level(ty: &str, past: isize) -> Option<String> {
    let past = usize::try_from(past).ok()?;
    Some(format!("{ty}{}", "*".repeat(past)))
}

/// What reading `name` -- one no declaration in scope binds -- can change,
/// judged as a body's free name is ([`DirectEffects::free_names`]), with
/// callees an object-like macro calls looked up in `base`.
/// `unknown_is_opaque` false judges a name nothing knows as reading nothing:
/// a rule looking at an identifier it has in hand, rather than at a body
/// that might hide a call behind it.
pub fn name_effects(
    name: &str,
    inputs: &EffectInputs,
    base: &dyn Fn(&str) -> Option<ClosedEffects>,
    unknown_is_opaque: bool,
) -> ClosedEffects {
    let index = HashMap::new();
    let mut own = ClosedEffects::default();
    let mut out = Vec::new();
    let mut resolver = Resolver {
        lenient: !unknown_is_opaque,
        inputs,
        index: &index,
        base,
        own: &mut own,
        out: &mut out,
    };
    resolver.free_name(name, 0);
    own.writes_any |= !own.writes.is_empty() || own.frame_write;
    own
}

/// The call `callee` in a macro body makes, when it hands on one of the
/// body's own parameters whole, as the invocation's `arg_objects` make it:
/// each such argument has the root the invocation's argument has.
fn forwarded_site(
    body: &macro_expand::MacroBodyCalls,
    callee: &str,
    arg_objects: &[ArgRoot],
) -> Option<CallSite> {
    let (_, passed) = body.forwarded.iter().find(|(c, _)| c == callee)?;
    let arg_objects = passed
        .iter()
        .map(|k| {
            k.and_then(|k| arg_objects.get(k).cloned())
                .unwrap_or(ArgRoot::Other)
        })
        .collect();
    Some(CallSite {
        callee: Some(callee.to_string()),
        arg_objects,
        ..Default::default()
    })
}

/// Where a callee's write lands, as its caller sees it.
enum Mapped {
    /// A location outside the caller's frame.
    To(Loc),
    /// The caller's own automatic storage, handed down by address.
    CallerFrame,
    /// Nowhere: the write goes through a null pointer argument, which a
    /// defined execution never does.
    Nowhere,
}

/// A callee's written location as its caller sees it.
fn map_through(loc: &Loc, args: &[ArgRoot]) -> Mapped {
    match loc {
        Loc::ParamPointee(k) => match args.get(*k) {
            Some(ArgRoot::Param(j)) => Mapped::To(Loc::ParamPointee(*j)),
            Some(ArgRoot::AddrOfGlobal(g)) => Mapped::To(Loc::Global(g.clone())),
            Some(ArgRoot::AddrOfLocal) => Mapped::CallerFrame,
            Some(ArgRoot::Null) => Mapped::Nowhere,
            Some(ArgRoot::Other) | None => Mapped::To(Loc::Unknown),
        },
        other => Mapped::To(other.clone()),
    }
}

/// Resolves one function's callees for the closure.
struct Resolver<'r, 'i> {
    /// A name or macro nothing can read is judged as reading nothing, not as
    /// unknown: set for a rule's own argument identifier, never for a body.
    lenient: bool,
    inputs: &'r EffectInputs<'i>,
    index: &'r HashMap<&'r str, usize>,
    base: &'r dyn Fn(&str) -> Option<ClosedEffects>,
    own: &'r mut ClosedEffects,
    out: &'r mut Vec<(usize, Vec<ArgRoot>)>,
}

impl Resolver<'_, '_> {
    /// Something could not be read: a name nothing declares, or a macro with
    /// no body the table can reason about. Unknown for a body; nothing for a
    /// rule's own argument identifier.
    fn unreadable(&mut self) {
        self.own.opaque |= !self.lenient;
    }

    /// Judge a name a body reads without declaring it: a project-wide
    /// volatile object is a volatile read; an object-like macro is what its
    /// replacement lists read, write and call; any other name the scan or the
    /// standard headers declare reads nothing; anything else is unknown.
    fn free_name(&mut self, name: &str, depth: usize) {
        let mut expanding = Vec::new();
        self.free_name_within(name, depth, &mut expanding);
    }

    /// [`Self::free_name`] inside the expansion of the object-like macros
    /// `expanding` names. A macro's own name in its replacement list is not
    /// replaced again (C11 6.10.3.4p2: `#define counter counter`, glibc's
    /// `#define stdin stdin`), so a name already being expanded is judged
    /// as the plain name it then is.
    fn free_name_within(&mut self, name: &str, depth: usize, expanding: &mut Vec<String>) {
        let names = self.inputs.names;
        if names.volatile_globals.contains(name) {
            // Matched by spelling across the scan (ADR-0006): when another
            // declaration gives the name without `volatile`, which object
            // this read reaches is not known.
            if names.non_volatile_globals.contains(name) {
                self.unreadable();
            } else {
                self.own.volatile_read = true;
            }
            return;
        }
        if let Some(defs) = names
            .macro_definitions
            .get(name)
            .filter(|_| !expanding.iter().any(|e| e == name))
        {
            use crate::analyze::check_macros::MacroDefinition;
            for def in defs {
                match def {
                    MacroDefinition::Object { body } => {
                        if depth > 4 {
                            self.unreadable();
                            continue;
                        }
                        expanding.push(name.to_string());
                        self.object_macro(body, depth, expanding);
                        expanding.pop();
                    }
                    // Named without a call: a function designator.
                    MacroDefinition::Function { .. } => {}
                    MacroDefinition::Opaque => self.unreadable(),
                }
            }
            return;
        }
        // A struct member or tag name is read where a macro argument names
        // one (`container_of(p, struct node, link)`); it is declared.
        let declared = names.global_objects.contains(name)
            || names.functions.contains(name)
            || names.constants.contains_key(name)
            || names.macros.contains(name)
            || names.typedefs.contains_key(name)
            || self.inputs.function_macro_names.contains(name)
            || self.inputs.struct_field_types.contains_key(name)
            || names.members.contains(name);
        if declared || !names.complete {
            return;
        }
        use crate::utility::cert_c::library_effects::{standard_object_name, StandardName};
        match standard_object_name(name) {
            Some(StandardName::Constant) => {}
            // Known only while the hosted library contract holds; at a rule's
            // own argument a stream is a name, not a call, and reads nothing.
            Some(StandardName::HostedStream) => self.own.lib_any |= !self.lenient,
            None if crate::utility::cert_c::std_functions::is_iso_c_or_posix_function(name) => {
                // A library function named without a call: a designator.
            }
            None => self.unreadable(),
        }
    }

    /// What an object-like macro's replacement list reads, writes and calls:
    /// `(*(volatile unsigned *)0x40000000u)` reads a volatile object,
    /// `get_tick()` calls, a nested macro recurses.
    fn object_macro(&mut self, body: &str, depth: usize, expanding: &mut Vec<String>) {
        let arm = MacroArm {
            params: Vec::new(),
            variadic: None,
            body: body.to_string(),
        };
        let calls = macro_expand::macro_body_calls(&arm);
        if calls.writes {
            self.own.writes.insert(Loc::Unknown);
            self.own.writes_any = true;
        }
        if calls.indirect {
            self.own.opaque = true;
        }
        for c in &calls.callees {
            self.classify(c, &CallSite::default(), depth + 1);
        }
        let names = self.inputs.names;
        for ident in macro_expand::body_identifiers(body) {
            if ident == "volatile" {
                self.own.volatile_read = true;
            } else if calls.callees.contains(&ident) {
                // Judged as a call above.
            } else if names.volatile_globals.contains(&ident)
                || names.macro_definitions.contains_key(&ident)
            {
                self.free_name_within(&ident, depth + 1, expanding);
            }
        }
    }

    /// Take a callee's closed effects from the base table as they are.
    fn absorb(&mut self, closed: &ClosedEffects, args: &[ArgRoot]) {
        self.own.absorb_flags(closed);
        for loc in &closed.writes {
            match map_through(loc, args) {
                Mapped::To(loc) => {
                    self.own.writes.insert(loc);
                    self.own.writes_any = true;
                }
                Mapped::CallerFrame => self.own.frame_write = true,
                Mapped::Nowhere => {}
            }
        }
    }

    /// What one definition of a function-like macro, invoked as `call`,
    /// writes and calls.
    fn macro_arm(&mut self, arm: &MacroArm, call: &CallSite, depth: usize) {
        let body = macro_expand::macro_body_calls(arm);
        if body.writes {
            self.own.writes.insert(Loc::Unknown);
            self.own.writes_any = true;
        }
        // Assigning a parameter writes what was passed there: nothing
        // outside the frame for the caller's own local, the object for a
        // named one, else something unknown.
        for &k in &body.written_params {
            let written = match call.arg_objects.get(k) {
                Some(ArgRoot::AddrOfLocal) => None,
                Some(ArgRoot::AddrOfGlobal(g)) => Some(Loc::Global(g.clone())),
                Some(ArgRoot::Param(j)) => Some(Loc::ParamPointee(*j)),
                Some(ArgRoot::Other | ArgRoot::Null) | None => Some(Loc::Unknown),
            };
            if let Some(loc) = written {
                self.own.writes.insert(loc);
                self.own.writes_any = true;
            }
        }
        if body.indirect {
            self.own.opaque = true;
        }
        let none = CallSite::default();
        for c in &body.callees {
            // A parameter handed on whole carries what the invocation
            // passed, so a nested macro assigning it writes that.
            let site = forwarded_site(&body, c, &call.arg_objects);
            self.classify(c, site.as_ref().unwrap_or(&none), depth + 1);
        }
        // A call through a parameter calls what the invocation passed there,
        // when that names a function.
        let passed = |k: usize| call.arg_functions.get(k).cloned().flatten();
        for k in body.param_calls {
            match passed(k) {
                Some(f) => self.classify(&f, &none, depth + 1),
                None => self.own.opaque = true,
            }
        }
        // `(t)(x)` calls a function passed there; with anything else, or
        // nothing known of the argument (an invocation inside another body),
        // it is a cast.
        for k in body.paren_param_calls {
            if let Some(f) = passed(k) {
                self.classify(&f, &none, depth + 1);
            }
        }
    }

    /// Resolve one callee name: a macro's body, a function being closed (an
    /// edge), a function the base table holds, a library function (by its
    /// contract, judged at query time), else something nothing summarizes.
    /// `call` carries what the invocation passed; a callee reached through
    /// a macro body, with nothing known of its arguments, passes an empty one.
    fn classify(&mut self, name: &str, call: &CallSite, depth: usize) {
        let args = call.args.as_slice();
        // A file-qualified key names a scanned static directly.
        if name.contains('\0') {
            match self.index.get(name) {
                Some(&i) => self.out.push((i, args.to_vec())),
                None => self.own.opaque = true,
            }
            return;
        }
        let inputs = self.inputs;
        let resolved = if inputs.function_macro_names.contains(name) {
            name
        } else {
            crate::analyze::const_eval::resolve_macro_alias(inputs.macro_aliases, name)
        };
        if is_effect_free_builtin(resolved) {
            return;
        }
        if inputs.function_macro_names.contains(resolved) {
            if depth > 4 {
                self.unreadable();
                return;
            }
            // Any header alternative may be the one compiled, so every arm
            // counts; a macro no header defines has its one definition.
            let one: Option<MacroArm>;
            let arms: Vec<&MacroArm> = match inputs.function_macro_arms.get(resolved) {
                Some(arms) if !arms.is_empty() => arms.iter().map(|p| &p.arm).collect(),
                _ => {
                    one = inputs.function_macros.get(resolved).map(MacroArm::from);
                    one.iter().collect()
                }
            };
            if arms.is_empty() {
                self.unreadable();
            }
            for arm in arms {
                self.macro_arm(arm, call, depth);
            }
            // An `#if` arm that does not define the macro may leave the name
            // a real function: that body counts too.
            if let Some(&i) = self.index.get(resolved) {
                self.out.push((i, args.to_vec()));
            } else if let Some(closed) = (self.base)(resolved) {
                self.absorb(&closed, args);
            }
            return;
        }
        if let Some(&i) = self.index.get(resolved) {
            self.out.push((i, args.to_vec()));
            return;
        }
        if let Some(closed) = (self.base)(resolved) {
            self.absorb(&closed, args);
            return;
        }
        if names_a_type(resolved, &inputs.names.typedefs) {
            return;
        }
        use crate::utility::cert_c::library_effects::{library_call_effect, LibraryEffect};
        match library_call_effect(resolved) {
            Some(effect) => {
                self.own.lib_any = true;
                match effect {
                    LibraryEffect::Pure => {}
                    LibraryEffect::OwnBufferOnly => self.own.lib_own_buffer = true,
                    LibraryEffect::SideEffect => self.own.lib_side_effect = true,
                }
            }
            None => self.own.opaque = true,
        }
    }
}

/// Whether a recorded member read reaches a member declared `volatile`. Only
/// a non-pointer member counts: the struct table records a pointer member's
/// type with one ` *` however deep it goes, so the dereferences needed to
/// reach a volatile object are unknown. `typedef_types` holds no struct
/// aliases, so a typedef reaches its struct only when alias and tag share a
/// name (the usual idiom).
fn chain_is_volatile(chain: &MemberChain, inputs: &EffectInputs) -> bool {
    let strip_pointer = |t: &str| {
        t.trim_end()
            .strip_suffix('*')
            .map(|s| s.trim_end().to_string())
    };
    let mut ty = chain.root_type.clone();
    for step in &chain.steps {
        let next = match step {
            Step::Deref => strip_pointer(&ty),
            Step::Field(field) => {
                let mut base = ty.clone();
                let mut found = None;
                for _ in 0..4 {
                    let Some(tag) = ast_utils::extract_struct_name_from_type(&base) else {
                        break;
                    };
                    if let Some(t) = inputs
                        .struct_field_types
                        .get(tag)
                        .and_then(|f| f.get(field))
                    {
                        found = Some(t.clone());
                        break;
                    }
                    match inputs.typedef_types.get(tag) {
                        Some(t) => base = t.clone(),
                        None => break,
                    }
                }
                found
            }
        };
        match next {
            Some(t) => ty = t,
            None => return false,
        }
    }
    // A member whose type is a volatile typedef (`reg_t ctrl;`) is as
    // volatile as one spelled `volatile`.
    matches!(chain.steps.last(), Some(Step::Field(_)))
        && !ty.contains('*')
        && ty
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|w| w == "volatile" || (!w.is_empty() && typedef_is_volatile(w, inputs.names)))
}

/// Strongly connected components of a graph given as adjacency lists, in
/// reverse topological order (every component after the ones it reaches).
/// Iterative, so a call chain of any depth costs heap, not stack.
fn tarjan_sccs(n: usize, edges: &[Vec<(usize, Vec<ArgRoot>)>]) -> Vec<Vec<usize>> {
    const UNVISITED: usize = usize::MAX;
    let mut index = vec![UNVISITED; n];
    let mut low = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<usize> = Vec::new();
    let mut sccs = Vec::new();
    let mut next_index = 0;
    for start in 0..n {
        if index[start] != UNVISITED {
            continue;
        }
        // (node, next edge position)
        let mut work: Vec<(usize, usize)> = vec![(start, 0)];
        index[start] = next_index;
        low[start] = next_index;
        next_index += 1;
        stack.push(start);
        on_stack[start] = true;
        while let Some(&mut (v, ref mut pos)) = work.last_mut() {
            if let Some((w, _)) = edges[v].get(*pos) {
                let w = *w;
                *pos += 1;
                if index[w] == UNVISITED {
                    index[w] = next_index;
                    low[w] = next_index;
                    next_index += 1;
                    stack.push(w);
                    on_stack[w] = true;
                    work.push((w, 0));
                } else if on_stack[w] {
                    low[v] = low[v].min(index[w]);
                }
                continue;
            }
            work.pop();
            if let Some(&(parent, _)) = work.last() {
                low[parent] = low[parent].min(low[v]);
            }
            if low[v] == index[v] {
                let mut scc = Vec::new();
                loop {
                    let w = stack.pop().expect("tarjan stack");
                    on_stack[w] = false;
                    scc.push(w);
                    if w == v {
                        break;
                    }
                }
                sccs.push(scc);
            }
        }
    }
    sccs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        parser.parse(code, None).unwrap()
    }

    fn direct(code: &str, function: &str) -> DirectEffects {
        let tree = parse(code);
        let root = tree.root_node();
        let arms = macro_expand::collect_function_macro_arms(code);
        let func =
            lang_parsing_substrate::query::find_descendants_of_kind(root, "function_definition")
                .into_iter()
                .find(|f| {
                    crate::analyze::function_summary::extract_function_name(f, code).as_deref()
                        == Some(function)
                })
                .expect("function");
        collect_direct_effects(&func, code, &arms, &FileScope::of(&root, code))
    }

    #[test]
    fn writes_are_located() {
        let code = "int g; static int s;\n\
            void f(int *p, int n, int *q) {\n\
              int local = 0; int arr[4]; static int count; int *lp = q;\n\
              local++; arr[1] = n; n = 2;\n\
              g = 1; s++; count += 1; *p = 3; q[2] = 4; *lp = 5;\n\
            }\n";
        let e = direct(code, "f");
        let expected: BTreeSet<Loc> = [
            Loc::Global("g".into()),
            Loc::Static("s".into()),
            Loc::Static("count".into()),
            Loc::ParamPointee(0),
            Loc::ParamPointee(2),
            Loc::Unknown,
        ]
        .into_iter()
        .collect();
        assert_eq!(e.writes, expected);
    }

    #[test]
    fn a_local_in_another_preprocessor_arm_does_not_hide_the_global() {
        let code = "int g;\n\
            void f(void) {\n\
            #ifdef LOCAL\n\
                int g;\n\
            #endif\n\
                g = 1;\n\
            }\n\
            void h(void) {\n\
            #ifdef LOCAL\n\
                int g;\n\
                g = 1;\n\
            #endif\n\
            }\n";
        assert_eq!(
            direct(code, "f").writes,
            [Loc::Global("g".into())].into_iter().collect()
        );
        assert!(direct(code, "h").writes.is_empty());
    }

    #[test]
    fn automatic_storage_is_not_a_write() {
        let code = "struct pt { int x; };\n\
            int f(int n) { int a[3]; struct pt v; a[0] = n; v.x = n; n++; return a[0] + v.x; }\n";
        assert!(direct(code, "f").writes.is_empty());
    }

    #[test]
    fn argument_roots() {
        let code = "int g;\n\
            void f(int *p, int n) { int x; int buf[2]; int *lp = p; h(p, &x, buf, &g, lp, n + 1, &p[1]); }\n";
        let e = direct(code, "f");
        assert_eq!(e.calls.len(), 1);
        let call = e.calls.iter().next().unwrap();
        assert_eq!(call.callee.as_deref(), Some("h"));
        assert_eq!(
            call.args,
            vec![
                ArgRoot::Param(0),
                ArgRoot::AddrOfLocal,
                ArgRoot::AddrOfLocal,
                ArgRoot::AddrOfGlobal("g".into()),
                ArgRoot::Other,
                ArgRoot::Other,
                ArgRoot::Param(0),
            ]
        );
    }

    #[test]
    fn a_file_macro_is_expanded_into_what_it_calls() {
        let code = "#define LOG(x) log_it(x)\n#define BUMP(x) ((x)++)\n\
            #define ZAP(p) (*(p) = 0)\n\
            void f(int n, int *q) { LOG(n); BUMP(n); ZAP(q); }\n\
            void g(int n) { BUMP(n); }\n";
        let e = direct(code, "f");
        assert!(e
            .calls
            .iter()
            .any(|c| c.callee.as_deref() == Some("log_it")));
        // The call itself is kept: an arm without the macro may leave the name a
        // function.
        assert!(e.calls.iter().any(|c| c.callee.as_deref() == Some("LOG")));
        // A macro body's write through its parameter is not located.
        assert!(e.writes.contains(&Loc::Unknown));
        // Assigning the parameter itself writes the argument: here the
        // function's own parameter, so nothing.
        assert!(direct(code, "g").writes.is_empty());
    }

    #[test]
    fn pointer_calls_and_asm_are_opaque() {
        let code = "int cmp(int a) { return a; }\n\
            int (*hook)(int);\n\
            void f(void (*cb)(void)) { cb(); }\n\
            int h(int (*cmp)(int)) { int (*local)(int) = cmp; return cmp(1) + local(2) + hook(3); }\n\
            int k(void) { return cmp(1); }\n\
            void g(void) { __asm__ volatile(\"nop\"); }\n";
        assert!(direct(code, "f").calls.iter().all(|c| c.callee.is_none()));
        // A parameter named like a scanned function is still a pointer.
        assert!(direct(code, "h").calls.iter().all(|c| c.callee.is_none()));
        assert!(direct(code, "k")
            .calls
            .iter()
            .any(|c| c.callee.as_deref() == Some("cmp")));
        // However the parser reads it, inline assembly is proven nothing.
        let ctx = scanned(&[("asm.c", code)], "asm");
        assert_eq!(ctx.effects().get("g").unwrap().proof(true), Proof::Unproven);
    }

    fn scanned(files: &[(&str, &str)], name: &str) -> crate::analyze::context::ProjectContext {
        let dir = std::env::temp_dir().join(format!("aurora-lint-side-effects-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (file, code) in files {
            std::fs::write(dir.join(file), code).unwrap();
        }
        crate::analyze::prescan::prescan_directories(
            &[dir.to_string_lossy().to_string()],
            None,
            false,
            &|_, _| false,
            Default::default(),
        )
        .unwrap()
    }

    const LIB: &str = "#include <string.h>\n#include <stdlib.h>\n\
        int counter;\n\
        int sq(int x) { return x * x; }\n\
        int bump(void) { return ++counter; }\n\
        void fill(int *p) { *p = 1; }\n\
        int fills_local(void) { int v; fill(&v); return v; }\n\
        void forwards(int *q) { fill(q); }\n\
        void fills_global(void) { fill(&counter); }\n\
        int ping(int n);\n\
        int pong(int n) { return n ? ping(n - 1) : 0; }\n\
        int ping(int n) { return n ? pong(n - 1) : sq(n); }\n\
        int rec_a(int n);\n\
        int rec_b(int n) { counter = n; return rec_a(n); }\n\
        int rec_a(int n) { return n ? rec_b(n - 1) : 0; }\n\
        size_t len(const char *s) { return strlen(s); }\n\
        long num(const char *s) { return strtol(s, 0, 10); }\n\
        int external(int);\n\
        int unproven(int n) { return external(n); }\n\
        int via_pointer(int (*f)(int)) { return f(1); }\n";

    #[test]
    fn closure_over_files() {
        let ctx = scanned(
            &[
                ("lib.c", LIB),
                ("use.c", "int use(void) { return sq(2) + bump(); }\n"),
            ],
            "closure",
        );
        let effects = ctx.effects();
        let proof = |n: &str, contract: bool| effects.get(n).unwrap().proof(contract);
        assert_eq!(proof("sq", true), Proof::Pure);
        assert_eq!(proof("bump", true), Proof::Impure);
        assert_eq!(proof("use", true), Proof::Impure);
        assert_eq!(proof("ping", true), Proof::Pure);
        assert_eq!(proof("pong", true), Proof::Pure);
        assert_eq!(proof("rec_a", true), Proof::Impure);
        assert_eq!(proof("rec_b", true), Proof::Impure);
        assert_eq!(proof("len", true), Proof::Pure);
        assert_eq!(proof("len", false), Proof::Unproven);
        assert_eq!(proof("num", true), Proof::Impure);
        assert_eq!(proof("unproven", true), Proof::Unproven);
        assert_eq!(proof("via_pointer", true), Proof::Unproven);

        // The mapped write sets.
        let writes = |n: &str| effects.get(n).unwrap().writes.clone();
        assert!(writes("fills_local").is_empty());
        assert!(effects.get("fills_local").unwrap().writes_any);
        assert_eq!(proof("fills_local", true), Proof::Unproven);
        assert_eq!(proof("fills_global", true), Proof::Impure);
        assert_eq!(
            writes("forwards"),
            [Loc::ParamPointee(0)].into_iter().collect()
        );
        assert_eq!(
            writes("fills_global"),
            [Loc::Global("counter".into())].into_iter().collect()
        );
    }

    #[test]
    fn a_static_resolves_to_its_own_file() {
        let a = "static int helper(void) { return 1; }\nint from_a(void) { return helper(); }\n";
        let b = "int g;\nstatic int helper(void) { return ++g; }\nint from_b(void) { return helper(); }\n";
        let ctx = scanned(&[("a.c", a), ("b.c", b)], "statics");
        let effects = ctx.effects();
        assert_eq!(effects.get("from_a").unwrap().proof(true), Proof::Pure);
        assert_eq!(effects.get("from_b").unwrap().proof(true), Proof::Impure);
    }

    #[test]
    fn a_long_chain_is_closed_without_recursion() {
        // Deeper than any thread stack would take recursively.
        const DEPTH: usize = 200_000;
        let mut facts: Vec<(String, DirectEffects)> = (0..DEPTH)
            .map(|i| {
                let mut d = DirectEffects::default();
                if i > 0 {
                    d.calls.insert(CallSite {
                        callee: Some(format!("f{}", i - 1)),
                        ..Default::default()
                    });
                }
                (format!("f{i}"), d)
            })
            .collect();
        facts[0].1.writes.insert(Loc::Global("g".into()));
        let names = std::collections::HashSet::new();
        let empty = HashMap::new();
        let table = EffectTable::build(
            facts.iter().map(|(k, v)| (k.clone(), v)),
            &EffectInputs {
                names: &ProjectNames::default(),
                function_macros: &HashMap::new(),
                function_macro_arms: &HashMap::new(),
                function_macro_names: &names,
                macro_aliases: &empty,
                struct_field_types: &HashMap::new(),
                typedef_types: &empty,
            },
        );
        let top = table.get(&format!("f{}", DEPTH - 1)).unwrap();
        assert_eq!(top.proof(true), Proof::Impure);
        assert_eq!(top.writes, [Loc::Global("g".into())].into_iter().collect());
    }

    fn pre31(
        ctx: &crate::analyze::context::ProjectContext,
        file: &str,
        code: &str,
        preset: &str,
    ) -> usize {
        use crate::settings::{AnalysisSettings, SettingsConfig};
        let registry = crate::rules::RuleRegistry::new();
        let rule = registry.get_rule("PRE31-C").unwrap();
        let config = SettingsConfig {
            profile: Some(preset.parse().unwrap()),
            ..Default::default()
        };
        let mut ctx = ctx.clone();
        ctx.settings = std::sync::Arc::new(AnalysisSettings::resolve(&config).unwrap());
        rule.set_analysis_settings(&ctx.settings);
        rule.set_project_context(&ctx);
        let tree = parse(code);
        let _ = file;
        rule.check(&tree.root_node(), code).len()
    }

    #[test]
    fn pre31_judges_callees_in_other_files() {
        let use_c = "#define TWICE(x) ((x) + (x))\n\
            int a(void) { return TWICE(sq(3)); }\n\
            int b(void) { return TWICE(bump()); }\n\
            int c(void) { return TWICE(unproven(1)); }\n";
        let ctx = scanned(&[("lib.c", LIB), ("use.c", use_c)], "pre31");
        // Default: only the proven-impure callee.
        assert_eq!(pre31(&ctx, "use.c", use_c, "default"), 1);
        // Strict: the unproven one too; the proven-pure one never.
        assert_eq!(pre31(&ctx, "use.c", use_c, "strict"), 2);
    }
    #[test]
    fn a_header_volatile_global_is_a_volatile_read_in_other_files() {
        let header = "extern volatile int g_ready;\n";
        let lib = "#include \"api.h\"\nint ready(void) { return g_ready; }\n";
        let use_c = "#define TWICE(x) ((x) + (x))\n\
            int a(void) { return TWICE(ready()); }\n\
            int b(void) { return TWICE(g_ready); }\n";
        let ctx = scanned(
            &[("api.h", header), ("lib.c", lib), ("use.c", use_c)],
            "volatile-header",
        );
        assert_eq!(
            ctx.effects().get("ready").unwrap().proof(true),
            Proof::Impure
        );
        assert_eq!(pre31(&ctx, "use.c", use_c, "default"), 2);
    }

    #[test]
    fn a_static_volatile_in_another_file_is_not_the_global_read() {
        // a.c's `static volatile int ready` is a different object from the
        // `ready` b.c defines, which is what c.c reads.
        let a = "static volatile int ready;\nvoid isr(void) { ready = 1; }\n";
        let b_h = "extern int ready;\n";
        let b = "#include \"b.h\"\nint ready;\n";
        let c = "#include \"b.h\"\n#define TWICE(x) ((x) + (x))\n\
            int get(void) { return ready; }\n\
            int u(void) { return TWICE(get()); }\n\
            int w(void) { return TWICE(ready); }\n";
        let ctx = scanned(
            &[("a.c", a), ("b.h", b_h), ("b.c", b), ("c.c", c)],
            "static-volatile",
        );
        assert_eq!(ctx.effects().get("get").unwrap().proof(true), Proof::Pure);
        assert_eq!(pre31(&ctx, "c.c", c, "default"), 0);

        // A name one file declares volatile and another without is not
        // known to be volatile: unproven, not a volatile read.
        let v_h = "extern volatile int flag;\n";
        let n = "int flag;\n";
        let g = "int get(void) { return flag; }\n";
        let ctx = scanned(&[("v.h", v_h), ("n.c", n), ("g.c", g)], "mixed-volatile");
        assert_eq!(
            ctx.effects().get("get").unwrap().proof(true),
            Proof::Unproven
        );
    }

    #[test]
    fn a_self_referential_object_macro_is_the_plain_name() {
        let header = "extern int counter;\n#define counter counter\n";
        let use_c = "int f(void) { return counter; }\n";
        let ctx = scanned(&[("c.h", header), ("use.c", use_c)], "self-referential");
        assert_eq!(ctx.effects().get("f").unwrap().proof(true), Proof::Pure);
    }

    #[test]
    fn a_pointer_typedef_or_member_typedef_to_volatile_is_a_volatile_read() {
        let header = "typedef volatile int *vptr;\n\
            typedef volatile unsigned reg_t;\n\
            struct regs { reg_t ctrl; unsigned plain; };\n";
        let a = "#include \"regs.h\"\n\
            vptr P;\n\
            struct regs *R;\n\
            int rd1(void) { return *P; }\n\
            unsigned rd2(void) { return R->ctrl; }\n\
            vptr rd3(void) { return P; }\n\
            unsigned rd4(void) { return R->plain; }\n";
        let ctx = scanned(
            &[("regs.h", header), ("a.c", a)],
            "volatile-typedef-siblings",
        );
        let proof = |n: &str| ctx.effects().get(n).unwrap().proof(true);
        assert_eq!(proof("rd1"), Proof::Impure);
        assert_eq!(proof("rd2"), Proof::Impure);
        // The pointer itself is not volatile, nor is a plain member.
        assert_eq!(proof("rd3"), Proof::Pure);
        assert_eq!(proof("rd4"), Proof::Pure);
    }

    #[test]
    fn a_macro_in_one_arm_does_not_hide_the_function_in_the_other() {
        let code = "int g;\n\
            #ifdef FAST_LOG\n\
            #define log_it(x) ((void)(x))\n\
            #else\n\
            void log_it(int x) { g = x; }\n\
            #endif\n\
            int f(int v) { log_it(v); return v; }\n";
        let ctx = scanned(&[("log.c", code)], "one-arm-macro");
        assert_eq!(ctx.effects().get("f").unwrap().proof(true), Proof::Impure);
    }

    #[test]
    fn a_write_through_a_null_argument_does_not_happen() {
        let code = "int hw;\n\
            int used(int *h) { if (h) *h = 3; return 1; }\n\
            int zero(void) { return used(0); }\n\
            int null(void) { return used(NULL); }\n\
            int cast(void) { return used((int *)0UL); }\n\
            int global(void) { return used(&hw); }\n\
            int local(void) { int v; return used(&v); }\n";
        let ctx = scanned(&[("s.c", code)], "null-arg");
        let effects = ctx.effects();
        for f in ["zero", "null", "cast"] {
            let e = effects.get(f).unwrap();
            assert_eq!(e.proof(true), Proof::Pure, "{f}");
            assert!(!e.writes_any, "{f}");
        }
        assert_eq!(effects.get("global").unwrap().proof(true), Proof::Impure);
        // The caller's own local is still written: unproven, not impure.
        let local = effects.get("local").unwrap();
        assert_eq!(local.proof(true), Proof::Unproven);
        assert!(local.frame_write);
        // At one call, the same judgement from the callee's own effects.
        let used = effects.get("used").unwrap();
        assert_eq!(used.proof(true), Proof::Impure);
        assert_eq!(
            used.past_null_arguments(|k| k == 0).proof(true),
            Proof::Pure
        );
    }

    #[test]
    fn a_header_iterator_writes_what_its_cursor_argument_names() {
        let header = "struct node { struct node *next; };\n\
            extern const struct node *cursor;\n\
            #define for_each_node(pos, head) \\\n\
                for ((pos) = (head); (pos) != 0; pos = (pos)->next)\n\
            #define for_each_live(pos, head) for_each_node(pos, head) if ((pos)->next)\n";
        let code = "#include \"list.h\"\n\
            const struct node *cursor;\n\
            int local(const struct node *h) { const struct node *n; int t = 0;\n\
                for_each_node(n, h) { t++; } return t; }\n\
            int global(const struct node *h) { int t = 0;\n\
                for_each_node(cursor, h) { t++; } return t; }\n\
            int member(struct node **pp, const struct node *h) { int t = 0;\n\
                for_each_node(pp[0], h) { t++; } return t; }\n\
            int nested(const struct node *h) { const struct node *n; int t = 0;\n\
                for_each_live(n, h) { t++; } return t; }\n\
            int nested_global(const struct node *h) { int t = 0;\n\
                for_each_live(cursor, h) { t++; } return t; }\n";
        let ctx = scanned(&[("list.h", header), ("walk.c", code)], "iter");
        let effects = ctx.effects();
        // The caller's own cursor: nothing outside its frame is written.
        assert_eq!(effects.get("local").unwrap().proof(true), Proof::Pure);
        // A global cursor is that global.
        let global = effects.get("global").unwrap();
        assert!(global.writes.contains(&Loc::Global("cursor".into())));
        // A cursor reached through a parameter is what it points to.
        let member = effects.get("member").unwrap();
        assert!(member.writes.contains(&Loc::ParamPointee(0)));
        assert!(!member.writes.contains(&Loc::Unknown));
        // Handed on to the macro that assigns it, the same.
        assert_eq!(effects.get("nested").unwrap().proof(true), Proof::Pure);
        let nested = effects.get("nested_global").unwrap();
        assert!(nested.writes.contains(&Loc::Global("cursor".into())));
    }

    #[test]
    fn every_header_definition_of_a_macro_counts() {
        // One macro's empty alternative comes first, the other's last, so
        // no single kept definition sees both effects.
        let header = "void log_write(int x);\n\
            int hits;\n\
            #ifdef NDEBUG\n\
            #define LOG(x) ((void)0)\n\
            #else\n\
            #define LOG(x) log_write(x)\n\
            #endif\n\
            #ifdef COUNT\n\
            #define TICK() (hits++)\n\
            #else\n\
            #define TICK() ((void)0)\n\
            #endif\n";
        let code = "#include \"log.h\"\n\
            int f(int k) { LOG(k); return k; }\n\
            int t(void) { TICK(); return 0; }\n";
        let ctx = scanned(&[("log.h", header), ("use.c", code)], "header-arms");
        let effects = ctx.effects();
        // The logging alternative calls a function nothing defines.
        assert_eq!(effects.get("f").unwrap().proof(true), Proof::Unproven);
        // The counting alternative writes.
        assert_eq!(effects.get("t").unwrap().proof(true), Proof::Impure);
    }

    #[test]
    fn an_unknown_name_is_unproven_and_a_standard_one_is_not() {
        let code = "#include <stdio.h>\n\
            int known(void) { return EOF + (NULL == 0); }\n\
            int unknown(void) { return MYSTERY_VALUE; }\n";
        let ctx = scanned(&[("n.c", code)], "unknown-name");
        let effects = ctx.effects();
        assert_eq!(effects.get("known").unwrap().proof(true), Proof::Pure);
        assert_eq!(effects.get("unknown").unwrap().proof(true), Proof::Unproven);
    }

    #[test]
    fn a_header_volatile_typedef_makes_a_read_through_it_volatile() {
        let header = "typedef volatile unsigned reg_t;\ntypedef reg_t reg2_t;\n";
        let lib = "#include \"regs.h\"\n\
            static reg2_t *R;\n\
            unsigned rd(void) { return *R; }\n\
            int mapped(void) { return R != 0; }\n";
        let ctx = scanned(&[("regs.h", header), ("lib.c", lib)], "volatile-typedef");
        let effects = ctx.effects();
        assert_eq!(effects.get("rd").unwrap().proof(true), Proof::Impure);
        assert_eq!(effects.get("mapped").unwrap().proof(true), Proof::Pure);
    }

    #[test]
    fn pre31_judges_the_files_own_functions_when_the_prescan_skipped_them() {
        // The prescan read only a header directory, as a `-d include` run does.
        let header =
            "int shared_counter;\nstatic inline int peek(void) { return shared_counter; }\n";
        let ctx = scanned(&[("api.h", header)], "pre31-headers-only");
        let code = "#define TWICE(x) ((x) + (x))\n\
            int g;\n\
            static int pure_local(int n) { return n * 2 + peek(); }\n\
            static int impure_local(void) { return ++g; }\n\
            int a(void) { return TWICE(pure_local(3)); }\n\
            int b(void) { return TWICE(impure_local()); }\n";
        assert_eq!(pre31(&ctx, "k.c", code, "default"), 1);
        assert_eq!(pre31(&ctx, "k.c", code, "strict"), 1);
    }
}
