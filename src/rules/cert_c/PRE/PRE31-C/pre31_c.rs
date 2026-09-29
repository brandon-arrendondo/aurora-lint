// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval::{merged_macro_aliases, resolve_macro_alias};
use crate::analyze::context::{ProjectContext, ScopedTable, VisibleTypes};
use crate::analyze::function_summary::{extract_function_name, FunctionSummary};
use crate::analyze::macro_expand::{self, ArgEvaluation, FunctionMacro, MacroArm, ProjectMacroArm};
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::{self, get_node_text, IdentifierBinding};
use crate::utility::cert_c::library_effects::{library_call_effect, LibraryEffect};
use crate::utility::cert_c::std_functions;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

pub struct Pre31C {
    /// Function-like macro definitions from the cross-file prescan
    /// (`ProjectContext::function_macros`) — needed because an unsafe
    /// macro's own `#define` usually lives in a header (curl's
    /// `DEBUGF`/`CURL_UNCONST` in `curl_setup.h`), not the file a call site
    /// sits in.
    function_macros: RefCell<Arc<HashMap<String, FunctionMacro>>>,
    /// Every definition of every function-like macro across the scanned
    /// headers (`ProjectContext::function_macro_arms`): a header's `#ifdef`
    /// alternatives, which `function_macros` reduces to one, each with the
    /// files that make it.
    function_macro_arms: RefCell<Arc<HashMap<String, Vec<ProjectMacroArm>>>>,
    /// The files this file's translation unit includes
    /// (`ProjectContext::include_closure`), when its includes were resolved.
    include_closure: RefCell<Option<Arc<HashSet<String>>>>,
    /// Every function-like macro name across the scanned files
    /// (`ProjectContext::function_macro_names`): what makes a call a macro
    /// invocation at all, whatever its spelling.
    function_macro_names: RefCell<Arc<HashSet<String>>>,
    /// Object-like aliases across the scanned files (`#define ASSERT assert`).
    macro_aliases: RefCell<Arc<HashMap<String, String>>>,
    /// Names only a header outside the project defines: the C library's own
    /// macros, which C11 7.1.4 binds (`library_macros_evaluate_once`).
    outside_macros: RefCell<Arc<HashSet<String>>>,
    /// Which functions some scanned file defines.
    function_summaries: RefCell<ScopedTable<FunctionSummary>>,
    /// Struct member and typedef types as this file sees them, for a read
    /// of a `volatile` member.
    types: RefCell<VisibleTypes>,
    /// `pre31_unknown_call_pure` and `stdlib_call_effects` decide how a
    /// call inside an argument is classified; `library_macros_evaluate_once`
    /// whether the C library's own macros are single-evaluation.
    settings: RefCell<Arc<AnalysisSettings>>,
}

impl Pre31C {
    pub fn new() -> Self {
        Self {
            function_macros: RefCell::new(Arc::new(HashMap::new())),
            function_macro_arms: RefCell::new(Arc::new(HashMap::new())),
            include_closure: RefCell::new(None),
            function_macro_names: RefCell::new(Arc::new(HashSet::new())),
            macro_aliases: RefCell::new(Arc::new(HashMap::new())),
            outside_macros: RefCell::new(Arc::new(HashSet::new())),
            function_summaries: RefCell::default(),
            types: RefCell::default(),
            settings: RefCell::new(Arc::new(AnalysisSettings::default())),
        }
    }
}

impl Default for Pre31C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Pre31C {
    fn rule_id(&self) -> &'static str {
        "PRE31-C"
    }

    fn description(&self) -> &'static str {
        "Avoid side effects in arguments to unsafe macros"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "PRE31-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_macros.borrow_mut() = context.function_macros.clone();
        *self.function_macro_arms.borrow_mut() = context.function_macro_arms.clone();
        *self.include_closure.borrow_mut() = context.include_closure.clone();
        *self.function_macro_names.borrow_mut() = context.function_macro_names.clone();
        *self.macro_aliases.borrow_mut() = context.macro_aliases.clone();
        *self.outside_macros.borrow_mut() = context.macros_defined_outside_project.clone();
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
    }

    fn set_visible_types(&self, types: &VisibleTypes) {
        *self.types.borrow_mut() = types.clone();
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        *self.settings.borrow_mut() = Arc::clone(settings);
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Cross-file (prescan) definitions first, then this file's own
        // `collect_function_macros` layered on top so a same-file
        // `#define` wins over a stale/differently-`#ifdef`'d cross-file one
        // — the "project-wide plus this file's own, per-file winning" idiom
        // `merged_macro_aliases` uses (see the capability catalog).
        let mut function_macros = HashMap::clone(&self.function_macros.borrow());
        function_macros.extend(macro_expand::collect_function_macros(node, source));
        let project_names = Arc::clone(&self.function_macro_names.borrow());
        let macro_names = macro_expand::FunctionMacroNames::new(source, &project_names);
        let mut local_functions: HashMap<String, Vec<Node>> = HashMap::new();
        for f in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(name) = extract_function_name(&f, source) {
                local_functions.entry(name).or_default().push(f);
            }
        }
        let settings = Arc::clone(&self.settings.borrow());
        let summaries = self.function_summaries.borrow();
        let types = self.types.borrow();
        let include_closure = self.include_closure.borrow().clone();
        let ctx = Ctx {
            source,
            names: &macro_names,
            first: &function_macros,
            arms: &macro_expand::collect_function_macro_arms(source),
            project_arms: &self.function_macro_arms.borrow(),
            include_closure: include_closure.as_deref(),
            aliases: &merged_macro_aliases(&self.macro_aliases.borrow(), node, source),
            outside: &self.outside_macros.borrow(),
            local_functions: &local_functions,
            summaries: &summaries,
            types: &types,
            settings: &settings,
            purity: RefCell::new(HashMap::new()),
            in_progress: RefCell::new(Vec::new()),
            lowest_reentered: std::cell::Cell::new(usize::MAX),
            provisional: RefCell::new(Vec::new()),
        };
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            // `#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED)` is not a macro
            // INVOCATION. When tree-sitter absorbs the directive into an ERROR,
            // `defined(X)` reparses as a call_expression and the condition's
            // other operands read as its "arguments" — so the rule reports a
            // side effect in an argument list that does not exist (ADR-0008).
            if ast_utils::is_on_preproc_directive_line(source, call_node.start_byte()) {
                continue;
            }
            self.check_macro_call(&call_node, &ctx, violations);
        }
    }
}

/// C library macros the standard lets evaluate an argument other than once,
/// and which argument: `assert`'s under `NDEBUG` (C11 7.2), the stream of
/// `getc`/`putc`/`getwc`/`putwc` (7.21.7.5, 7.21.7.8, 7.29.3.6, 7.29.3.9).
/// C11 7.1.4 requires every other library macro to evaluate each argument
/// exactly once.
fn library_unsafe_argument(name: &str) -> Option<usize> {
    match name {
        "assert" | "getc" | "getwc" => Some(0),
        "putc" | "putwc" => Some(1),
        _ => None,
    }
}

/// How an argument's evaluation can change program state, from least to
/// most certain. The rule reports [`Effect::Definite`] under every policy,
/// and [`Effect::Unknown`] and [`Effect::Unanalyzed`] (an unproven call)
/// only when `pre31_unknown_call_pure` is withdrawn (the strict policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Effect {
    /// Shown to change nothing: operators that do not write, and calls to
    /// callees proven pure (PRE31-C-EX1).
    None,
    /// A call to a function no scanned file defines and no library contract
    /// covers (or one through a pointer), or to a library function whose only
    /// effect is the static buffer it returns (`strerror`, `getenv`, ...).
    Unknown,
    /// A call to a function another scanned file defines. Its body is in the
    /// scan but no cross-file side-effect summary exists yet, so it is
    /// neither proven pure nor proven impure: an unproven call, like
    /// [`Effect::Unknown`].
    Unanalyzed,
    /// A write (`=`, compound assignment, `++`/`--`), a volatile read, or a
    /// call to a callee shown to have a side effect.
    Definite,
}

/// Everything one file's scan needs to classify arguments.
struct Ctx<'a> {
    source: &'a str,
    names: &'a macro_expand::FunctionMacroNames<'a>,
    /// One definition per name (project-wide, this file's winning).
    first: &'a HashMap<String, FunctionMacro>,
    /// This file's definitions, every preprocessor branch, variadic and
    /// `#`/`##` arms included.
    arms: &'a HashMap<String, Vec<MacroArm>>,
    /// Every scanned header's definitions, the same way, with their files.
    project_arms: &'a HashMap<String, Vec<ProjectMacroArm>>,
    /// `Pre31C::include_closure`.
    include_closure: Option<&'a HashSet<String>>,
    aliases: &'a HashMap<String, String>,
    /// `Pre31C::outside_macros`.
    outside: &'a HashSet<String>,
    /// This file's function definitions, by name: every `#if` arm's.
    local_functions: &'a HashMap<String, Vec<Node<'a>>>,
    summaries: &'a ScopedTable<FunctionSummary>,
    types: &'a VisibleTypes,
    settings: &'a AnalysisSettings,
    /// Final verdicts on this file's functions.
    purity: RefCell<HashMap<String, Effect>>,
    /// Functions being judged, outermost first. Re-entering one reads as
    /// [`Effect::None`] (its own body is being counted already).
    in_progress: RefCell<Vec<String>>,
    /// The lowest `in_progress` position re-entered since the current
    /// judgment began: a verdict that leaned on an enclosing function's
    /// unfinished one is provisional until that function finishes.
    lowest_reentered: std::cell::Cell<usize>,
    /// Finished judgments still waiting on an enclosing unfinished one (the
    /// open members of a recursive group), in completion order, with the
    /// lowest position each re-entered. Reused, not recomputed, until the
    /// group's head finishes and hands every member its verdict.
    provisional: RefCell<Vec<(String, Effect, usize)>>,
}

impl<'a> Ctx<'a> {
    /// The definitions a call to `name` may expand to: every arm in this
    /// file, else every arm of the headers this file includes (every arm the
    /// project has when that is unknown), else the one expandable definition
    /// the project keeps. Two headers may define one name two ways; a call
    /// is compiled with the one its translation unit includes (ADR-0006).
    fn definitions(&self, name: &str) -> Vec<MacroArm> {
        if let Some(arms) = self.arms.get(name).filter(|arms| !arms.is_empty()) {
            return arms.clone();
        }
        let arms = macro_expand::reachable_arms(self.project_arms, name, self.include_closure);
        if !arms.is_empty() {
            return arms;
        }
        self.first
            .get(name)
            .map(MacroArm::from)
            .into_iter()
            .collect()
    }

    /// The name a call's callee spelling denotes: a function-like macro's own
    /// name, else where its object-like alias chain ends.
    fn resolve<'n>(&'n self, name: &'n str) -> &'n str {
        if self.names.contains(name) {
            name
        } else {
            resolve_macro_alias(self.aliases, name)
        }
    }

    /// Whether this report's policy counts `effect` as a side effect.
    fn reported(&self, effect: Effect) -> bool {
        match effect {
            Effect::Definite => true,
            Effect::Unknown | Effect::Unanalyzed => !self.settings.flag("pre31_unknown_call_pure"),
            Effect::None => false,
        }
    }

    /// The side effect evaluating `node` may have.
    fn expression_effect(&self, node: &Node<'a>) -> Effect {
        match node.kind() {
            "update_expression" | "assignment_expression" => Effect::Definite,
            // Operands C11 leaves unevaluated (a VLA `sizeof` aside).
            "sizeof_expression" | "alignof_expression" | "string_literal" | "char_literal" => {
                Effect::None
            }
            "identifier" => {
                if self.is_volatile(node) {
                    Effect::Definite
                } else {
                    Effect::None
                }
            }
            "field_expression" if self.is_volatile_member(node) => Effect::Definite,
            // The controlling expression is not evaluated (C11 6.5.1.1p3).
            "generic_expression" => {
                let mut cursor = node.walk();
                node.named_children(&mut cursor)
                    .skip(1)
                    .map(|c| self.expression_effect(&c))
                    .max()
                    .unwrap_or(Effect::None)
            }
            "call_expression" => {
                let callee = match node.child_by_field_name("function") {
                    Some(f) if f.kind() == "identifier" => {
                        self.callee_effect(get_node_text(&f, self.source), 0)
                    }
                    // Through a pointer or a member: nothing names the body,
                    // and the callee expression may itself have effects.
                    Some(f) => self.expression_effect(&f).max(Effect::Unknown),
                    None => Effect::Unknown,
                };
                let args = node
                    .child_by_field_name("arguments")
                    .map_or(Effect::None, |a| self.children_effect(&a));
                callee.max(args)
            }
            _ => self.children_effect(node),
        }
    }

    fn children_effect(&self, node: &Node<'a>) -> Effect {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .map(|c| self.expression_effect(&c))
            .max()
            .unwrap_or(Effect::None)
    }

    /// Whether an identifier occurrence reads a volatile object, resolved to
    /// its declaration (ADR-0006), never matched by spelling. A declaration's
    /// own `volatile` qualifies what its pointers and arrays finally reach,
    /// so `volatile T *p` makes `*p`, `p->f` and `p[i]` volatile reads and
    /// `p` itself not; `T *volatile p` makes `p` one.
    fn is_volatile(&self, ident: &Node<'a>) -> bool {
        let name = get_node_text(ident, self.source);
        let Some((decl, declarator)) =
            ast_utils::resolve_identifier_declarator(ident, name, self.source)
        else {
            return false;
        };
        let mut levels = 0;
        let mut own_qualifier = false;
        let mut node = Some(declarator);
        while let Some(d) = node {
            match d.kind() {
                "pointer_declarator" | "array_declarator" => {
                    levels += 1;
                    let inner = d.child_by_field_name("declarator");
                    if d.kind() == "pointer_declarator"
                        && inner.is_some_and(|i| i.kind() == "identifier")
                        && ast_utils::declaration_has_qualifier(&d, "volatile", self.source)
                    {
                        own_qualifier = true;
                    }
                    node = inner;
                }
                _ => node = None,
            }
        }
        let derefs = dereferences_applied(ident, self.source);
        // `&x` takes the address; nothing is read.
        derefs >= 0
            && (own_qualifier
                || (ast_utils::declaration_has_qualifier(&decl, "volatile", self.source)
                    && derefs >= levels as isize))
    }

    /// Whether a member access reads a member declared `volatile`. Only a
    /// non-pointer member counts: the struct table records a pointer member's
    /// type with one ` *` however deep it goes (`volatile u32 **apWiData`),
    /// so the dereferences needed to reach the volatile object are unknown
    /// and `p->apWiData[i]` (a pointer read) must not be reported. A volatile
    /// base object is caught at its identifier by [`Self::is_volatile`].
    fn is_volatile_member(&self, member: &Node<'a>) -> bool {
        // `&p->nRef` takes the address; nothing is read.
        dereferences_applied(member, self.source) >= 0
            && self.expression_type(member).is_some_and(|ty| {
                !ty.contains('*')
                    && ty
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .any(|w| w == "volatile")
            })
    }

    /// The declared type of an lvalue expression built from a scope-resolved
    /// identifier (ADR-0006), members read from the visible struct tables.
    /// `typedef_types` holds no struct aliases, so a typedef reaches its
    /// struct only when the alias and the tag share a name (`typedef struct
    /// sqlite3_mutex sqlite3_mutex;`, the usual idiom).
    fn expression_type(&self, node: &Node<'a>) -> Option<String> {
        let strip_pointer = |t: String| {
            t.trim_end()
                .strip_suffix('*')
                .map(|s| s.trim_end().to_string())
        };
        match node.kind() {
            "identifier" => {
                let name = get_node_text(node, self.source);
                ast_utils::resolve_identifier_declared_type(node, name, self.source)
            }
            "parenthesized_expression" => self.expression_type(&node.named_child(0)?),
            "pointer_expression" => {
                strip_pointer(self.expression_type(&node.child_by_field_name("argument")?)?)
            }
            "subscript_expression" => {
                strip_pointer(self.expression_type(&node.child_by_field_name("argument")?)?)
            }
            "field_expression" => {
                let field = get_node_text(&node.child_by_field_name("field")?, self.source);
                let mut base = self.expression_type(&node.child_by_field_name("argument")?)?;
                for _ in 0..4 {
                    let tag = ast_utils::extract_struct_name_from_type(&base)?.to_string();
                    if let Some(ty) = self
                        .types
                        .struct_field_types
                        .get(&tag)
                        .and_then(|f| f.get(field))
                    {
                        return Some(ty.clone());
                    }
                    base = self.types.typedef_types.get(&tag)?.clone();
                }
                None
            }
            _ => None,
        }
    }

    /// The side effect of calling `name` (as spelled at the call site).
    fn callee_effect(&self, name: &str, depth: usize) -> Effect {
        if depth > 4 {
            return Effect::Unknown;
        }
        let name = self.resolve(name);
        // A nested assert changes nothing the program goes on with: it
        // evaluates its condition (judged where it is written) or aborts.
        if matches!(name, "assert" | "static_assert" | "_Static_assert")
            || PURE_BUILTINS.contains(&name)
        {
            return Effect::None;
        }
        if self.names.contains(name) {
            return self.macro_effect(name, depth);
        }
        if let Some(defs) = self.local_functions.get(name) {
            return self.function_effect(name, defs);
        }
        if self.summaries.contains_key(name) {
            return Effect::Unanalyzed;
        }
        if self.settings.flag("stdlib_call_effects") {
            match library_call_effect(name) {
                Some(LibraryEffect::Pure) => return Effect::None,
                Some(LibraryEffect::SideEffect) => return Effect::Definite,
                // Only its own returned buffer changes: relaxed with the
                // unknown-callee bucket (default), reported under strict.
                Some(LibraryEffect::OwnBufferOnly) => return Effect::Unknown,
                None => {}
            }
        }
        Effect::Unknown
    }

    /// A function-like macro invoked inside the argument: its body is its
    /// only definition, so judge what the body writes and calls.
    fn macro_effect(&self, name: &str, depth: usize) -> Effect {
        let defs = self.definitions(name);
        if defs.is_empty() {
            return Effect::Unknown;
        }
        defs.iter()
            .map(|arm| {
                let (writes, callees) = macro_expand::macro_body_effects(arm);
                if writes {
                    return Effect::Definite;
                }
                callees
                    .iter()
                    .map(|c| self.callee_effect(c, depth + 1))
                    .max()
                    .unwrap_or(Effect::None)
            })
            .max()
            .unwrap_or(Effect::None)
    }

    /// The side effect of calling a function this file defines: a write to
    /// anything but its own automatic objects, a volatile read, or a call
    /// with one (PRE31-C-EX1's "does nothing but perform a computation").
    /// With several `#if` definitions, the worst of them: this use accuses,
    /// so an effect in any configuration counts.
    ///
    /// Mutually recursive functions share one verdict, found with Tarjan's
    /// strongly connected components: each body is walked once, a finished
    /// member of a group whose head is still being judged is reused from
    /// `provisional`, and when the head finishes every member gets the
    /// head's verdict, which by then covers all of their bodies.
    fn function_effect(&self, name: &str, defs: &[Node<'a>]) -> Effect {
        if let Some(e) = self.purity.borrow().get(name) {
            return *e;
        }
        if let Some(pos) = self.in_progress.borrow().iter().position(|n| n == name) {
            self.lowest_reentered
                .set(self.lowest_reentered.get().min(pos));
            return Effect::None;
        }
        let open = self
            .provisional
            .borrow()
            .iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, e, low)| (*e, *low));
        if let Some((effect, low)) = open {
            self.lowest_reentered
                .set(self.lowest_reentered.get().min(low));
            return effect;
        }
        let depth = self.in_progress.borrow().len();
        let mark = self.provisional.borrow().len();
        self.in_progress.borrow_mut().push(name.to_string());
        let outer_lowest = self.lowest_reentered.replace(usize::MAX);
        let effect = defs
            .iter()
            .map(|def| {
                def.child_by_field_name("body")
                    .map_or(Effect::Unknown, |body| self.body_effect(&body))
            })
            .max()
            .unwrap_or(Effect::Unknown);
        self.in_progress.borrow_mut().pop();
        let lowest = self.lowest_reentered.get();
        if lowest >= depth {
            // This function heads its group: the group is complete.
            let members = self.provisional.borrow_mut().split_off(mark);
            let mut purity = self.purity.borrow_mut();
            for (member, _, _) in members {
                purity.insert(member, effect);
            }
            purity.insert(name.to_string(), effect);
        } else {
            self.provisional
                .borrow_mut()
                .push((name.to_string(), effect, lowest));
        }
        self.lowest_reentered.set(outer_lowest.min(lowest));
        effect
    }

    fn body_effect(&self, node: &Node<'a>) -> Effect {
        match node.kind() {
            "assignment_expression" | "update_expression" => {
                let target = node
                    .child_by_field_name("left")
                    .or_else(|| node.child_by_field_name("argument"));
                let write = match target {
                    Some(t) if self.is_automatic_lvalue(&t) => Effect::None,
                    _ => Effect::Definite,
                };
                write.max(self.body_children_effect(node))
            }
            "identifier" => {
                if self.is_volatile(node) {
                    Effect::Definite
                } else {
                    Effect::None
                }
            }
            "field_expression" if self.is_volatile_member(node) => Effect::Definite,
            "call_expression" => {
                let callee = match node.child_by_field_name("function") {
                    Some(f) if f.kind() == "identifier" => {
                        self.callee_effect(get_node_text(&f, self.source), 0)
                    }
                    Some(f) => self.body_effect(&f).max(Effect::Unknown),
                    None => Effect::Unknown,
                };
                let args = node
                    .child_by_field_name("arguments")
                    .map_or(Effect::None, |a| self.body_children_effect(&a));
                callee.max(args)
            }
            "gnu_asm_expression" => Effect::Unknown,
            "sizeof_expression" | "alignof_expression" | "string_literal" | "char_literal" => {
                Effect::None
            }
            _ => self.body_children_effect(node),
        }
    }

    fn body_children_effect(&self, node: &Node<'a>) -> Effect {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .map(|c| self.body_effect(&c))
            .max()
            .unwrap_or(Effect::None)
    }

    /// Whether an lvalue designates storage the function owns and discards
    /// on return: a parameter itself, a non-static local, or an element or
    /// member of a local array or struct (not reached through a pointer).
    fn is_automatic_lvalue(&self, lvalue: &Node<'a>) -> bool {
        match lvalue.kind() {
            "parenthesized_expression" => lvalue
                .named_child(0)
                .is_some_and(|inner| self.is_automatic_lvalue(&inner)),
            "identifier" => self.is_automatic_object(lvalue, false),
            "subscript_expression" => lvalue.child_by_field_name("argument").is_some_and(|base| {
                base.kind() == "identifier" && self.is_automatic_object(&base, true)
            }),
            "field_expression" => {
                let through_pointer = lvalue
                    .child_by_field_name("operator")
                    .is_some_and(|op| get_node_text(&op, self.source) == "->");
                !through_pointer
                    && lvalue
                        .child_by_field_name("argument")
                        .is_some_and(|base| self.is_automatic_lvalue(&base))
            }
            _ => false,
        }
    }

    /// Whether an identifier resolves to a parameter or a non-static local.
    /// `element_access`: the lvalue indexes it, so it must be a local array
    /// (a parameter "array" is a pointer to the caller's storage).
    fn is_automatic_object(&self, ident: &Node<'a>, element_access: bool) -> bool {
        let name = get_node_text(ident, self.source);
        match ast_utils::resolve_identifier_binding(ident, name, self.source) {
            Some(IdentifierBinding::Parameter(_)) => !element_access,
            Some(IdentifierBinding::Local(decl)) => {
                !ast_utils::declaration_has_storage_class(&decl, "static", self.source)
                    && (!element_access
                        || ast_utils::declaration_declarator_for(&decl, name, self.source)
                            .is_some_and(|d| d.kind() == "array_declarator"))
            }
            _ => false,
        }
    }
}

/// How many dereferences the expression around a node applies to it:
/// `*p`, `p[i]` and `p->f` one each, `&x` minus one. Negative when only the
/// address is taken.
fn dereferences_applied(node: &Node, source: &str) -> isize {
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

/// Compiler builtins that compute a value and change nothing (GCC manual,
/// "Other Built-in Functions"): `likely(x)` inside an assert is not an
/// unknown call.
const PURE_BUILTINS: &[&str] = &[
    "__builtin_expect",
    "__builtin_expect_with_probability",
    "__builtin_constant_p",
    "__builtin_types_compatible_p",
    "__builtin_choose_expr",
    "__builtin_offsetof",
    "__builtin_object_size",
    "__builtin_dynamic_object_size",
];

impl Pre31C {
    fn check_macro_call(&self, node: &Node, ctx: &Ctx, violations: &mut Vec<RuleViolation>) {
        let Some(function_node) = node.child_by_field_name("function") else {
            return;
        };
        let spelled = get_node_text(&function_node, ctx.source);
        let macro_name = ctx.resolve(spelled);
        let arms = ctx.arms.get(macro_name).filter(|a| !a.is_empty());

        // Which argument positions this macro may evaluate other than once.
        // A macro this file defines is judged by every arm it has, since any
        // one may be the one compiled; a C library macro by what the standard
        // permits (the libc header the prescan read is one implementation);
        // a project macro defined elsewhere by every definition the project
        // has; a macro whose body nobody can read at every position.
        // An argument the body hands to another function-like macro is
        // evaluated as that macro evaluates it.
        let forward = |name: &str| {
            let name = ctx.resolve(name);
            if ctx.names.contains(name) {
                ctx.definitions(name)
            } else {
                Vec::new()
            }
        };
        let evaluates_once = move |a: &MacroArm, i| {
            macro_expand::argument_evaluation_through(a, i, &forward) == ArgEvaluation::Once
        };
        let unsafe_at: Box<dyn Fn(usize) -> bool + '_> = if let Some(arms) = arms {
            let arms = arms.clone();
            Box::new(move |i| arms.iter().any(|a| !evaluates_once(a, i)))
        } else if let Some(k) = library_unsafe_argument(macro_name) {
            Box::new(move |i| i == k)
        } else if ctx.outside.contains(macro_name)
            && std_functions::is_iso_c_function(macro_name)
            && ctx.settings.flag("library_macros_evaluate_once")
        {
            // The implementation's macro for a library function: whatever
            // its body looks like, C11 7.1.4 has it evaluate each argument
            // once (glibc's tolower reads `c` twice through __tobody).
            return;
        } else if ctx.names.contains(macro_name) {
            let defs = ctx.definitions(macro_name);
            if defs.is_empty() {
                Box::new(|_| true)
            } else {
                Box::new(move |i| defs.iter().any(|a| !evaluates_once(a, i)))
            }
        } else {
            return;
        };

        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        let args = arguments
            .named_children(&mut cursor)
            .filter(|a| a.kind() != "comment");
        for (i, arg) in args.enumerate() {
            if !unsafe_at(i) || !ctx.reported(ctx.expression_effect(&arg)) {
                continue;
            }
            let start_point = node.start_position();
            let severity = if macro_name == "assert" {
                Severity::Medium // assert is disabled in release builds
            } else {
                Severity::High
            };
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity,
                message: format!(
                    "Unsafe macro '{}' called with side effect in argument {}: '{}'",
                    spelled,
                    i + 1,
                    get_node_text(&arg, ctx.source).trim()
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(
                    "Move side effects outside macro call or use inline function".to_string(),
                ),
                ..Default::default()
            });
        }
    }
}
