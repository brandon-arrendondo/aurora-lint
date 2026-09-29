// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval::{merged_macro_aliases, resolve_macro_alias};
use crate::analyze::context::{EffectView, IncludeClosure, ProjectContext, VisibleTypes};
use crate::analyze::function_summary::extract_function_name;
use crate::analyze::macro_expand::{self, ArgEvaluation, FunctionMacro, MacroArm, ProjectMacroArm};
use crate::analyze::side_effects::{
    collect_direct_effects, dereferences_applied, designates_object, is_null_pointer_constant,
    is_type_name_text, is_volatile_read, names_a_type, typedef_is_volatile, typedef_read,
    EffectInputs, EffectTable, FileScope, Proof, PURE_BUILTINS,
};
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::library_effects::{library_call_effect, LibraryEffect};
use crate::utility::cert_c::std_functions;
use lang_parsing_substrate::query;
use std::cell::{OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
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
    /// The resolved include graph (`ProjectContext::include_edges`), for the
    /// closure of the file being checked.
    include_edges: RefCell<Arc<HashMap<String, Vec<String>>>>,
    /// The file being checked.
    file_path: RefCell<Option<PathBuf>>,
    /// Every function-like macro name across the scanned files
    /// (`ProjectContext::function_macro_names`): what makes a call a macro
    /// invocation at all, whatever its spelling.
    function_macro_names: RefCell<Arc<HashSet<String>>>,
    /// Object-like aliases across the scanned files (`#define ASSERT assert`).
    macro_aliases: RefCell<Arc<HashMap<String, String>>>,
    /// Names only a header outside the project defines: the C library's own
    /// macros, which C11 7.1.4 binds (`library_macros_evaluate_once`).
    outside_macros: RefCell<Arc<HashSet<String>>>,
    /// What calling each scanned function can change, closed over the call
    /// graph of the whole scan. `None` when no prescan context was given.
    effects: RefCell<Option<EffectView>>,
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
            include_edges: RefCell::new(Arc::new(HashMap::new())),
            file_path: RefCell::new(None),
            function_macro_names: RefCell::new(Arc::new(HashSet::new())),
            macro_aliases: RefCell::new(Arc::new(HashMap::new())),
            outside_macros: RefCell::new(Arc::new(HashSet::new())),
            effects: RefCell::default(),
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
        *self.include_edges.borrow_mut() = context.include_edges.clone();
        *self.function_macro_names.borrow_mut() = context.function_macro_names.clone();
        *self.macro_aliases.borrow_mut() = context.macro_aliases.clone();
        *self.outside_macros.borrow_mut() = context.macros_defined_outside_project.clone();
        *self.effects.borrow_mut() = Some(context.effects());
    }

    fn set_visible_types(&self, types: &VisibleTypes) {
        *self.types.borrow_mut() = types.clone();
    }

    fn set_file_path(&self, path: &Path) {
        *self.file_path.borrow_mut() = Some(path.to_path_buf());
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
        let settings = Arc::clone(&self.settings.borrow());
        let arms = macro_expand::collect_function_macro_arms(source);
        let project_arms = Arc::clone(&self.function_macro_arms.borrow());
        let aliases = merged_macro_aliases(&self.macro_aliases.borrow(), node, source);
        let types = self.types.borrow();
        // The file's own functions, closed here with their calls into the
        // rest of the scan answered by the table. When the prescan read this
        // file, the table's entry already covers these bodies. When it did
        // not (a `-d` naming only the include directories, or no prescan at
        // all), a same-named function elsewhere is a different definition, so
        // the worse of the two answers.
        let effects = self.effects.borrow().clone();
        let file_scope = FileScope::of(node, source);
        let mut direct: HashMap<String, crate::analyze::side_effects::DirectEffects> =
            HashMap::new();
        for f in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(name) = extract_function_name(&f, source) {
                direct
                    .entry(name)
                    .or_default()
                    .merge(collect_direct_effects(&f, source, &arms, &file_scope));
            }
        }
        let include_edges = self.include_edges.borrow();
        let file_path = self.file_path.borrow();
        let names_known = effects
            .as_ref()
            .map(|v| v.names.clone())
            .unwrap_or_default();
        let local_table = (!direct.is_empty()).then(|| {
            let mut names: HashSet<String> = HashSet::clone(&project_names);
            names.extend(function_macros.keys().cloned());
            EffectTable::build_over(
                direct.iter().map(|(k, v)| (k.clone(), v)),
                &EffectInputs {
                    names: &names_known,
                    function_macros: &function_macros,
                    function_macro_arms: &project_arms,
                    function_macro_names: &names,
                    macro_aliases: &aliases,
                    struct_field_types: &types.struct_field_types,
                    typedef_types: &types.typedef_types,
                },
                &|name| effects.as_ref().and_then(|v| v.get(name).cloned()),
            )
        });
        let ctx = Ctx {
            source,
            names: &macro_names,
            first: &function_macros,
            arms: &arms,
            project_arms: &project_arms,
            include_edges: &include_edges,
            file_path: file_path.as_deref(),
            include_closure: OnceCell::new(),
            aliases: &aliases,
            outside: &self.outside_macros.borrow(),
            effects: effects.as_ref(),
            local_table: local_table.as_ref(),
            types: &types,
            settings: &settings,
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
/// and [`Effect::Unknown`] (an unproven call) only when
/// `pre31_unknown_call_pure` is withdrawn (the strict policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Effect {
    /// Shown to change nothing: operators that do not write, and calls to
    /// callees proven pure (PRE31-C-EX1).
    None,
    /// A call nothing proves either way: to a function no scanned file
    /// defines and no library contract covers, through a pointer, to a
    /// library function whose only effect is the static buffer it returns
    /// (`strerror`, `getenv`, ...), or to a scanned function that reaches
    /// one of these and nothing worse.
    Unknown,
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
    /// `Pre31C::include_edges`.
    include_edges: &'a HashMap<String, Vec<String>>,
    /// `Pre31C::file_path`.
    file_path: Option<&'a Path>,
    /// This file's include closure, walked the first time a name has more
    /// than one project definition to choose between.
    include_closure: OnceCell<Option<IncludeClosure>>,
    aliases: &'a HashMap<String, String>,
    /// `Pre31C::outside_macros`.
    outside: &'a HashSet<String>,
    /// The scan's side-effect table, as this file resolves names.
    effects: Option<&'a EffectView>,
    /// This file's own functions, closed over the scan's table.
    local_table: Option<&'a EffectTable>,
    types: &'a VisibleTypes,
    settings: &'a AnalysisSettings,
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
        let closure = if self
            .project_arms
            .get(name)
            .is_some_and(|arms| arms.len() > 1)
        {
            self.include_closure
                .get_or_init(|| {
                    self.file_path
                        .and_then(|path| IncludeClosure::of(self.include_edges, path))
                })
                .as_ref()
        } else {
            None
        };
        let arms = macro_expand::reachable_arms(self.project_arms, name, closure);
        if !arms.is_empty() {
            return arms;
        }
        self.first
            .get(name)
            .map(MacroArm::from)
            .into_iter()
            .collect()
    }

    /// Whether `name` is the C library's own macro for a library function
    /// (only a header outside the project defines it) while
    /// `library_macros_evaluate_once` holds: C11 7.1.4 then has it evaluate
    /// each argument exactly once, like the function, whatever its body
    /// reads. The standard's own exceptions (`library_unsafe_argument`: getc's
    /// stream, putc's) are not bound by it.
    fn bound_by_library_contract(&self, name: &str) -> bool {
        self.outside.contains(name)
            && std_functions::is_iso_c_function(name)
            && library_unsafe_argument(name).is_none()
            && self.settings.flag("library_macros_evaluate_once")
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
            Effect::Unknown => !self.settings.flag("pre31_unknown_call_pure"),
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
                if is_volatile_read(node, self.source) || self.reads_volatile_typedef(node) {
                    Effect::Definite
                } else {
                    self.free_name_effect(node)
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
                let arguments = node.child_by_field_name("arguments");
                let callee = match node.child_by_field_name("function") {
                    // A parameter, local or function pointer named like a
                    // function is still a call through a pointer (ADR-0006).
                    Some(f) if f.kind() == "identifier" && designates_object(&f, self.source) => {
                        Effect::Unknown
                    }
                    Some(f) if f.kind() == "identifier" => {
                        self.call_effect(get_node_text(&f, self.source), arguments.as_ref(), 0)
                    }
                    // Through a pointer or a member: nothing names the body,
                    // and the callee expression may itself have effects.
                    Some(f) => self.expression_effect(&f).max(Effect::Unknown),
                    None => Effect::Unknown,
                };
                let args = arguments.map_or(Effect::None, |a| self.children_effect(&a));
                callee.max(args)
            }
            _ => self.children_effect(node),
        }
    }

    /// Whether an identifier reads an object whose typedef is volatile
    /// (`typedef volatile uint32_t reg_t;`, usually in a header).
    fn reads_volatile_typedef(&self, ident: &Node<'a>) -> bool {
        let Some(view) = self.effects else {
            return false;
        };
        typedef_read(ident, self.source).is_some_and(|t| typedef_is_volatile(&t, &view.names))
    }

    /// A name nothing in this file declares in scope (a header's `extern
    /// volatile` object, an object-like macro such as `NOW` expanding to a
    /// call), judged against the project as a callee's free names are, except
    /// that a name nothing knows is not unknown here.
    fn free_name_effect(&self, ident: &Node<'a>) -> Effect {
        let Some(view) = self.effects else {
            return Effect::None;
        };
        let name = get_node_text(ident, self.source);
        if ast_utils::resolve_identifier_binding(ident, name, self.source).is_some() {
            return Effect::None;
        }
        // An identifier in the argument is not a call: only what the project
        // shows it to be (a volatile object, a macro that calls or writes)
        // counts, and a name nothing knows reads nothing here.
        match view
            .name_effects(name, false)
            .proof(self.settings.flag("stdlib_call_effects"))
        {
            Proof::Pure => Effect::None,
            Proof::Unproven => Effect::Unknown,
            Proof::Impure => Effect::Definite,
        }
    }

    fn children_effect(&self, node: &Node<'a>) -> Effect {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .map(|c| self.expression_effect(&c))
            .max()
            .unwrap_or(Effect::None)
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
        self.call_effect(name, None, depth)
    }

    /// [`Self::callee_effect`] for a call whose argument list is at hand, so
    /// a macro calling one of its parameters resolves to the function passed
    /// there.
    fn call_effect(&self, name: &str, arguments: Option<&Node<'a>>, depth: usize) -> Effect {
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
            // An `#if` arm that does not define the macro may leave the name
            // a real function: the worse of the two.
            let as_macro = self.macro_effect(name, arguments, depth);
            return match self.function_effect(name, arguments) {
                Some(f) => as_macro.max(f),
                None => as_macro,
            };
        }
        if let Some(effect) = self.function_effect(name, arguments) {
            return effect;
        }
        // A type "called" in a macro body is a cast (`(T)(x)`).
        let no_typedefs = HashMap::new();
        let typedefs = self.effects.map_or(&no_typedefs, |v| &*v.names.typedefs);
        if names_a_type(name, typedefs) {
            return Effect::None;
        }
        let stdlib_contract = self.settings.flag("stdlib_call_effects");
        if stdlib_contract {
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

    /// What calling a scanned function can change, when the scan defines it.
    fn function_effect(&self, name: &str, arguments: Option<&Node<'a>>) -> Option<Effect> {
        let stdlib_contract = self.settings.flag("stdlib_call_effects");
        let local = self.local_table.and_then(|t| t.get(name));
        let project = self.effects.and_then(|v| v.get(name));
        let closed = match (local, project) {
            (Some(l), Some(p)) => Some(l.union(p)),
            (l, p) => l.or(p).cloned(),
        };
        // The conservative reading: a callee writing through a pointer it
        // was handed counts, whatever the caller handed it -- except a null
        // pointer, through which nothing is written.
        let passed: Vec<Node<'a>> = arguments
            .map(|a| {
                let mut cursor = a.walk();
                a.named_children(&mut cursor)
                    .filter(|c| c.kind() != "comment")
                    .collect()
            })
            .unwrap_or_default();
        let null = |k: usize| {
            passed
                .get(k)
                .is_some_and(|a| is_null_pointer_constant(a, self.source))
        };
        closed.map(
            |closed| match closed.past_null_arguments(null).proof(stdlib_contract) {
                Proof::Pure => Effect::None,
                Proof::Unproven => Effect::Unknown,
                Proof::Impure => Effect::Definite,
            },
        )
    }

    /// A function-like macro invoked inside the argument: its body is its
    /// only definition, so judge what the body writes and calls. A call
    /// through one of its parameters calls what `arguments` passes there; a
    /// call through a member or a pointer names no body.
    fn macro_effect(&self, name: &str, arguments: Option<&Node<'a>>, depth: usize) -> Effect {
        let defs = self.definitions(name);
        if defs.is_empty() {
            return Effect::Unknown;
        }
        let passed: Vec<Node<'a>> = arguments
            .map(|a| {
                let mut cursor = a.walk();
                a.named_children(&mut cursor)
                    .filter(|c| c.kind() != "comment")
                    .collect()
            })
            .unwrap_or_default();
        defs.iter()
            .map(|arm| {
                let body = macro_expand::macro_body_calls(arm);
                // Inside the argument, assigning even the caller's own local
                // is the side effect.
                if body.writes || !body.written_params.is_empty() {
                    return Effect::Definite;
                }
                let direct = body
                    .callees
                    .iter()
                    .map(|c| self.callee_effect(c, depth + 1));
                let through_params = body.param_calls.iter().map(|&k| {
                    let arg = passed
                        .get(k)
                        .map(crate::analyze::init_state::strip_arg_casts);
                    match arg {
                        Some(a)
                            if a.kind() == "identifier" && !designates_object(&a, self.source) =>
                        {
                            self.callee_effect(get_node_text(&a, self.source), depth + 1)
                        }
                        _ => Effect::Unknown,
                    }
                });
                // `(t)(x)`: a function passed there is called; a type is a
                // cast; another expression is a call through it; nothing
                // passed (an invocation inside another body) is a cast.
                let through_paren_params = body.paren_param_calls.iter().map(|&k| {
                    let Some(a) = passed
                        .get(k)
                        .map(crate::analyze::init_state::strip_arg_casts)
                    else {
                        return Effect::None;
                    };
                    if a.kind() == "identifier" && !designates_object(&a, self.source) {
                        self.callee_effect(get_node_text(&a, self.source), depth + 1)
                    } else if is_type_name_text(get_node_text(&a, self.source)) {
                        Effect::None
                    } else {
                        Effect::Unknown
                    }
                });
                let indirect = body.indirect.then_some(Effect::Unknown);
                direct
                    .chain(through_params)
                    .chain(through_paren_params)
                    .chain(indirect)
                    .max()
                    .unwrap_or(Effect::None)
            })
            .max()
            .unwrap_or(Effect::None)
    }
}

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
            if ctx.names.contains(name) && !ctx.bound_by_library_contract(name) {
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
        } else if ctx.bound_by_library_contract(macro_name) {
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
