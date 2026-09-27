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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CallSite {
    /// The callee as spelled, or `None` for a call through a pointer or a
    /// member (nothing names the body).
    pub callee: Option<String>,
    /// One root per argument, in order. Empty for a callee reached through a
    /// macro body, whose arguments are not separated.
    pub args: Vec<ArgRoot>,
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
    pub calls: Vec<CallSite>,
    /// Inline assembly: anything may change.
    pub opaque: bool,
}

impl DirectEffects {
    /// Fold another definition of the same name in: `#if` alternatives or
    /// build-variant files, any of which may be the one compiled, so the
    /// union governs.
    pub fn merge(&mut self, other: DirectEffects) {
        self.writes.extend(other.writes);
        self.volatile_read |= other.volatile_read;
        self.member_chains.extend(other.member_chains);
        for call in other.calls {
            if !self.calls.contains(&call) {
                self.calls.push(call);
            }
        }
        self.opaque |= other.opaque;
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
        let mut cursor = root.walk();
        for decl in root.children(&mut cursor) {
            if decl.kind() != "declaration" {
                continue;
            }
            let mut inner = decl.walk();
            for child in decl.children(&mut inner) {
                let declarator = match child.kind() {
                    "init_declarator" => child.child_by_field_name("declarator").unwrap_or(child),
                    "identifier"
                    | "pointer_declarator"
                    | "array_declarator"
                    | "function_declarator" => child,
                    _ => continue,
                };
                let name = ast_utils::get_identifier_from_declarator(&declarator, source);
                if !name.is_empty() {
                    globals.entry(name).or_insert(decl);
                }
            }
        }
        let volatile_names = source.contains("volatile").then(|| {
            lang_parsing_substrate::query::find_descendants(*root, |n| {
                matches!(n.kind(), "declaration" | "parameter_declaration")
            })
            .into_iter()
            .filter(|d| get_node_text(d, source).contains("volatile"))
            .flat_map(|d| {
                let mut cursor = d.walk();
                d.children(&mut cursor)
                    .map(|c| ast_utils::get_identifier_from_declarator(&c, source))
                    .filter(|n| !n.is_empty())
                    .collect::<Vec<_>>()
            })
            .collect()
        });
        FileScope {
            globals,
            volatile_names,
        }
    }
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
        arms,
        scope,
        out: DirectEffects::default(),
    };
    if let Some(body) = func.child_by_field_name("body") {
        collector.walk(&body);
    }
    collector.out
}

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
                "identifier" if self.reads_volatile(&node) => {
                    self.out.volatile_read = true;
                }
                // `&p->f` takes the address; nothing is read.
                "field_expression" if dereferences_applied(&node, self.source) >= 0 => {
                    if let Some(chain) = self.member_chain(&node) {
                        self.out.member_chains.insert(chain);
                    }
                }
                "call_expression" => self.call(&node),
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
        if let Some(name) = &callee {
            if let Some(arms) = self.arms.get(name).filter(|a| !a.is_empty()) {
                for arm in arms {
                    let (writes, callees) = macro_expand::macro_body_effects(arm);
                    if writes {
                        self.out.writes.insert(Loc::Unknown);
                    }
                    for c in callees {
                        self.push_call(CallSite {
                            callee: Some(c),
                            args: Vec::new(),
                        });
                    }
                }
                return;
            }
        }
        let args = node
            .child_by_field_name("arguments")
            .map(|a| {
                let mut cursor = a.walk();
                a.named_children(&mut cursor)
                    .filter(|c| c.kind() != "comment")
                    .map(|c| self.arg_root(&c))
                    .collect()
            })
            .unwrap_or_default();
        self.push_call(CallSite { callee, args });
    }

    fn push_call(&mut self, call: CallSite) {
        if !self.out.calls.contains(&call) {
            self.out.calls.push(call);
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
            Some(IdentifierBinding::Local(decl)) => {
                if ast_utils::declaration_has_storage_class(&decl, "static", self.source) {
                    Some(Loc::Static(name.to_string()))
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

    fn arg_root(&self, arg: &Node<'t>) -> ArgRoot {
        let arg = crate::analyze::init_state::strip_arg_casts(arg);
        match arg.kind() {
            "identifier" => {
                let name = get_node_text(&arg, self.source);
                match self.binding(&arg) {
                    Some(IdentifierBinding::Parameter(_)) => self
                        .params
                        .iter()
                        .position(|p| p == name)
                        .map_or(ArgRoot::Other, ArgRoot::Param),
                    // A local array decays to its own storage's address.
                    Some(IdentifierBinding::Local(decl))
                        if is_automatic_local_array(&decl, &arg, self.source) =>
                    {
                        ArgRoot::AddrOfLocal
                    }
                    _ => ArgRoot::Other,
                }
            }
            "pointer_expression"
                if arg
                    .child_by_field_name("operator")
                    .is_some_and(|op| get_node_text(&op, self.source) == "&") =>
            {
                let Some(operand) = arg.child_by_field_name("argument") else {
                    return ArgRoot::Other;
                };
                match self.write_location(&operand) {
                    None => ArgRoot::AddrOfLocal,
                    Some(Loc::Global(g) | Loc::Static(g)) => ArgRoot::AddrOfGlobal(g),
                    // `&p[i]`, `&p->f`: inside what parameter `j` points to.
                    Some(Loc::ParamPointee(j)) => ArgRoot::Param(j),
                    Some(Loc::Unknown) => ArgRoot::Other,
                }
            }
            _ => ArgRoot::Other,
        }
    }
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

/// Whether `decl` (a block-scope declaration binding `ident`) declares a
/// non-static array: storage the function owns.
fn is_automatic_local_array(decl: &Node, ident: &Node, source: &str) -> bool {
    !ast_utils::declaration_has_storage_class(decl, "static", source)
        && ast_utils::declaration_declarator_for(decl, get_node_text(ident, source), source)
            .is_some_and(|d| d.kind() == "array_declarator")
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

    fn absorb_flags(&mut self, other: &ClosedEffects) {
        self.writes_any |= other.writes_any;
        self.volatile_read |= other.volatile_read;
        self.lib_side_effect |= other.lib_side_effect;
        self.lib_own_buffer |= other.lib_own_buffer;
        self.lib_any |= other.lib_any;
        self.opaque |= other.opaque;
    }
}

/// The project tables the closure resolves callees and member types against.
pub struct EffectInputs<'a> {
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
            for call in &direct.calls {
                match &call.callee {
                    Some(name) => {
                        let mut resolver = Resolver {
                            inputs,
                            index: &index,
                            base,
                            own: &mut own,
                            out: &mut out,
                        };
                        resolver.classify(name, &call.args, 0)
                    }
                    None => own.opaque = true,
                }
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
            // Mapped writes: to a fixpoint within the group.
            let mut writes: HashMap<usize, BTreeSet<Loc>> =
                scc.iter().map(|&m| (m, local[m].writes.clone())).collect();
            for _pass in 0..64 {
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
    /// Resolve one callee name: a macro's body, a function being closed (an
    /// edge), a function the base table holds, a library function (by its
    /// contract, judged at query time), else something nothing summarizes.
    fn classify(&mut self, name: &str, args: &[ArgRoot], depth: usize) {
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
            let Some(def) = inputs.function_macros.get(resolved) else {
                self.own.opaque = true;
                return;
            };
            let (writes, callees) = macro_expand::macro_body_effects(&MacroArm::from(def));
            if writes {
                self.own.writes.insert(Loc::Unknown);
                self.own.writes_any = true;
            }
            for c in callees {
                self.classify(&c, &[], depth + 1);
            }
            return;
        }
        if let Some(&i) = self.index.get(resolved) {
            self.out.push((i, args.to_vec()));
            return;
        }
        if let Some(closed) = (self.base)(resolved) {
            self.own.absorb_flags(&closed);
            self.own.writes.extend(
                closed
                    .writes
                    .iter()
                    .filter_map(|loc| map_through(loc, args)),
            );
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
        assert_eq!(e.calls[0].callee.as_deref(), Some("h"));
        assert_eq!(
            e.calls[0].args,
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
        assert!(!e.calls.iter().any(|c| c.callee.as_deref() == Some("LOG")));
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
        assert_eq!(direct(code, "k").calls[0].callee.as_deref(), Some("cmp"));
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
                    d.calls.push(CallSite {
                        callee: Some(format!("f{}", i - 1)),
                        args: Vec::new(),
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
