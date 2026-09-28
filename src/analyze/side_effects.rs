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
}

/// One call in a body.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
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

/// The file-scope objects and enumeration constants `root` declares, and the
/// objects among them declared `volatile`, `#if` blocks included. Functions
/// are not objects.
pub fn file_scope_objects(
    root: &Node,
    source: &str,
) -> (
    std::collections::HashSet<String>,
    std::collections::HashSet<String>,
) {
    let mut objects = std::collections::HashSet::new();
    let mut volatile = std::collections::HashSet::new();
    for (name, decl) in file_scope_declarators(root, source) {
        let Some(declarator) = ast_utils::declaration_declarator_for(&decl, &name, source) else {
            continue;
        };
        if declares_function(&declarator) {
            continue;
        }
        if ast_utils::declaration_has_qualifier(&decl, "volatile", source) {
            volatile.insert(name.clone());
        }
        objects.insert(name);
    }
    // Enumeration constants are declared names too, whatever block their
    // `enum` is in, and whether or not a value is written.
    for e in lang_parsing_substrate::query::find_descendants_of_kind(*root, "enumerator") {
        if let Some(n) = e.child_by_field_name("name") {
            objects.insert(get_node_text(&n, source).to_string());
        }
    }
    (objects, volatile)
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
        let (args, arg_functions): (Vec<ArgRoot>, Vec<Option<String>>) = node
            .child_by_field_name("arguments")
            .map(|a| {
                let mut cursor = a.walk();
                a.named_children(&mut cursor)
                    .filter(|c| c.kind() != "comment")
                    .map(|c| self.arg_root(&c))
                    .unzip()
            })
            .unwrap_or_default();
        if let Some(name) = &callee {
            if let Some(arms) = self.arms.get(name).filter(|a| !a.is_empty()) {
                for arm in arms {
                    let body = macro_expand::macro_body_calls(arm);
                    if body.writes {
                        self.out.writes.insert(Loc::Unknown);
                    }
                    let reached = body
                        .callees
                        .into_iter()
                        .map(Some)
                        // A call through a parameter calls what is passed
                        // there; an argument that names no function, or a
                        // call through a member or a pointer, names no body.
                        .chain(
                            body.param_calls
                                .iter()
                                .map(|&k| arg_functions.get(k).cloned().flatten()),
                        )
                        .chain(body.indirect.then_some(None));
                    for callee in reached {
                        self.out.calls.insert(CallSite {
                            callee,
                            args: Vec::new(),
                            arg_functions: Vec::new(),
                        });
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
        self.out.calls.insert(CallSite {
            callee,
            args,
            arg_functions,
        });
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
            // spelling names the object outside (`int g; ... #ifdef LOCAL
            // int g; #endif g = 1;`), so the write counts.
            Some(IdentifierBinding::Local(decl)) if in_other_arm(&decl, ident) => {
                Some(Loc::Global(name.to_string()))
            }
            Some(IdentifierBinding::Local(decl)) => {
                if ast_utils::declaration_has_storage_class(&decl, "static", self.source) {
                    Some(Loc::Static(name.to_string()))
                } else if ast_utils::declaration_has_storage_class(&decl, "extern", self.source) {
                    // `extern int hits;` in a block names the file-scope object.
                    Some(Loc::Global(name.to_string()))
                } else if element && !is_automatic_local_array(&decl, ident, self.source) {
                    Some(Loc::Unknown)
                } else {
                    None
                }
            }
            Some(IdentifierBinding::Global(decl)) => {
                if ast_utils::declaration_has_storage_class(&decl, "static", self.source) {
                    Some(Loc::Static(name.to_string()))
                } else {
                    Some(Loc::Global(name.to_string()))
                }
            }
            None => Some(Loc::Global(name.to_string())),
        }
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
        if let Some(decl) =
            ast_utils::find_enclosing_declaration_for_identifier(ident, name, self.source)
        {
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
        (dereferences_applied(ident, self.source) >= levels).then_some(ty)
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
                let Some(operand) = arg.child_by_field_name("argument") else {
                    return (ArgRoot::Other, None);
                };
                let root = match self.write_location(&operand) {
                    None => ArgRoot::AddrOfLocal,
                    Some(Loc::Global(g) | Loc::Static(g)) => ArgRoot::AddrOfGlobal(g),
                    // `&p[i]`, `&p->f`: inside what parameter `j` points to.
                    Some(Loc::ParamPointee(j)) => ArgRoot::Param(j),
                    Some(Loc::Unknown) => ArgRoot::Other,
                };
                (root, None)
            }
            _ => (ArgRoot::Other, None),
        }
    }
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
    /// Some write happens, this function's own or any callee's, before any
    /// argument mapping: the conservative reading, in which a callee that
    /// writes through a pointer it was handed counts even when the caller
    /// handed it a local.
    pub writes_any: bool,
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
    /// The conservative verdict: any write counts, a callee's write through
    /// a pointer argument included. `stdlib_contract` is the
    /// `stdlib_call_effects` environment contract: withdrawn, a library
    /// callee is as unknown as any other body-less one.
    pub fn proof(&self, stdlib_contract: bool) -> Proof {
        if self.writes_any || self.volatile_read || (stdlib_contract && self.lib_side_effect) {
            Proof::Impure
        } else if self.opaque
            || (stdlib_contract && self.lib_own_buffer)
            || (!stdlib_contract && self.lib_any)
        {
            Proof::Unproven
        } else {
            Proof::Pure
        }
    }

    /// Everything either may change: the worse of two definitions.
    pub fn union(&self, other: &ClosedEffects) -> ClosedEffects {
        let mut out = self.clone();
        out.absorb_flags(other);
        out.writes.extend(other.writes.iter().cloned());
        out
    }

    fn absorb_flags(&mut self, other: &ClosedEffects) {
        self.writes_any |= other.writes_any;
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
                inputs,
                index: &index,
                base,
                own: &mut own,
                out: &mut out,
            };
            for call in &direct.calls {
                match &call.callee {
                    Some(name) => resolver.classify(name, &call.args, &call.arg_functions, 0),
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
                        add.extend(
                            callee_writes
                                .into_iter()
                                .flatten()
                                .filter_map(|loc| map_through(loc, args)),
                        );
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
                result.writes_any |= !result.writes.is_empty();
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

/// Whether a typedef name denotes a volatile-qualified type: its own
/// definition says `volatile`, or it aliases, through `typedefs`, one that
/// does.
pub fn typedef_is_volatile(name: &str, names: &ProjectNames) -> bool {
    let mut current = name;
    for _ in 0..8 {
        if names.volatile_typedefs.contains(current) {
            return true;
        }
        match names.typedefs.get(current) {
            Some(next) => current = next.as_str(),
            None => return false,
        }
    }
    false
}

/// The typedef names `root` defines with `volatile` in their type
/// (`typedef volatile uint32_t reg_t;`), `#if` blocks included. A pointer
/// typedef (`typedef volatile int *vptr;`) is not one: the typedef names the
/// pointer, not the volatile object.
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
                .filter(|d| d.kind() == "type_identifier")
                .map(|d| get_node_text(&d, source).to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The typedef an identifier read reads an object of at the level the
/// typedef names, resolved to its declaration (ADR-0006): for a rule judging
/// an expression it has in hand.
pub fn typedef_read(ident: &Node, source: &str) -> Option<String> {
    let name = get_node_text(ident, source);
    let (decl, _) = ast_utils::resolve_identifier_declarator(ident, name, source)?;
    let (ty, levels) = typedef_declaration(&decl, name, source)?;
    (dereferences_applied(ident, source) >= levels).then_some(ty)
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
        inputs,
        index: &index,
        base,
        own: &mut own,
        out: &mut out,
    };
    resolver.free_name_with(name, 0, unknown_is_opaque);
    own
}

/// A callee's written location as its caller sees it; `None` when the
/// caller handed the callee its own automatic storage.
fn map_through(loc: &Loc, args: &[ArgRoot]) -> Option<Loc> {
    match loc {
        Loc::ParamPointee(k) => match args.get(*k) {
            Some(ArgRoot::Param(j)) => Some(Loc::ParamPointee(*j)),
            Some(ArgRoot::AddrOfGlobal(g)) => Some(Loc::Global(g.clone())),
            Some(ArgRoot::AddrOfLocal) => None,
            _ => Some(Loc::Unknown),
        },
        other => Some(other.clone()),
    }
}

/// Resolves one function's callees for the closure.
struct Resolver<'r, 'i> {
    inputs: &'r EffectInputs<'i>,
    index: &'r HashMap<&'r str, usize>,
    base: &'r dyn Fn(&str) -> Option<ClosedEffects>,
    own: &'r mut ClosedEffects,
    out: &'r mut Vec<(usize, Vec<ArgRoot>)>,
}

impl Resolver<'_, '_> {
    /// Judge a name a body reads without declaring it: a project-wide
    /// volatile object is a volatile read; an object-like macro is what its
    /// replacement lists read, write and call; any other name the scan or the
    /// standard headers declare reads nothing; anything else is unknown.
    fn free_name(&mut self, name: &str, depth: usize) {
        self.free_name_with(name, depth, true);
    }

    /// [`Self::free_name`]; `unknown_is_opaque` false leaves a name nothing
    /// knows as reading nothing instead of unknown.
    fn free_name_with(&mut self, name: &str, depth: usize, unknown_is_opaque: bool) {
        let names = self.inputs.names;
        if names.volatile_globals.contains(name) {
            self.own.volatile_read = true;
            return;
        }
        if let Some(defs) = names.macro_definitions.get(name) {
            use crate::analyze::check_macros::MacroDefinition;
            for def in defs {
                match def {
                    MacroDefinition::Object { body } => {
                        if depth > 4 {
                            self.own.opaque = true;
                            continue;
                        }
                        self.object_macro(body, depth);
                    }
                    // Named without a call: a function designator.
                    MacroDefinition::Function { .. } => {}
                    MacroDefinition::Opaque => self.own.opaque = true,
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
            // Known only while the hosted library contract holds.
            Some(StandardName::HostedStream) => self.own.lib_any = true,
            None if crate::utility::cert_c::std_functions::is_iso_c_or_posix_function(name) => {
                // A library function named without a call: a designator.
            }
            None => self.own.opaque |= unknown_is_opaque,
        }
    }

    /// What an object-like macro's replacement list reads, writes and calls:
    /// `(*(volatile unsigned *)0x40000000u)` reads a volatile object,
    /// `get_tick()` calls, a nested macro recurses.
    fn object_macro(&mut self, body: &str, depth: usize) {
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
            self.classify(c, &[], &[], depth + 1);
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
                self.free_name(&ident, depth + 1);
            }
        }
    }

    /// Take a callee's closed effects from the base table as they are.
    fn absorb(&mut self, closed: &ClosedEffects, args: &[ArgRoot]) {
        self.own.absorb_flags(closed);
        self.own.writes.extend(
            closed
                .writes
                .iter()
                .filter_map(|loc| map_through(loc, args)),
        );
    }

    /// Resolve one callee name: a macro's body, a function being closed (an
    /// edge), a function the base table holds, a library function (by its
    /// contract, judged at query time), else something nothing summarizes.
    fn classify(
        &mut self,
        name: &str,
        args: &[ArgRoot],
        arg_functions: &[Option<String>],
        depth: usize,
    ) {
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
                self.own.opaque = true;
                return;
            }
            match inputs.function_macros.get(resolved) {
                Some(def) => {
                    let body = macro_expand::macro_body_calls(&MacroArm::from(def));
                    if body.writes {
                        self.own.writes.insert(Loc::Unknown);
                        self.own.writes_any = true;
                    }
                    if body.indirect {
                        self.own.opaque = true;
                    }
                    for c in body.callees {
                        self.classify(&c, &[], &[], depth + 1);
                    }
                    // A call through a parameter calls what the invocation
                    // passed there, when that names a function.
                    for k in body.param_calls {
                        match arg_functions.get(k).cloned().flatten() {
                            Some(f) => self.classify(&f, &[], &[], depth + 1),
                            None => self.own.opaque = true,
                        }
                    }
                }
                None => self.own.opaque = true,
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
    matches!(chain.steps.last(), Some(Step::Field(_)))
        && !ty.contains('*')
        && ty
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|w| w == "volatile")
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
            void f(int n) { LOG(n); BUMP(n); }\n";
        let e = direct(code, "f");
        assert!(e
            .calls
            .iter()
            .any(|c| c.callee.as_deref() == Some("log_it")));
        // The call itself is kept: an arm without the macro may leave the name a
        // function.
        assert!(e.calls.iter().any(|c| c.callee.as_deref() == Some("LOG")));
        // A macro body's write is not located.
        assert!(e.writes.contains(&Loc::Unknown));
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
                        args: Vec::new(),
                        arg_functions: Vec::new(),
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
