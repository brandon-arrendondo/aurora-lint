// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval::{merged_macro_aliases, resolve_macro_alias};
use crate::analyze::context::{
    EffectView, IncludeClosure, ProjectContext, VisibleTypes, UNRESOLVED_INCLUDE,
};
use crate::analyze::dead_regions::{self, ConfiguredLines};
use crate::analyze::function_summary::extract_function_name;
use crate::analyze::macro_expand::{
    self, ArgEvaluation, ArmSite, FunctionMacro, MacroArm, Pasting, ProjectMacroArm,
};
use crate::analyze::preproc_arms::PreprocArms;
use crate::analyze::side_effects::{
    collect_direct_effects, dereferences_applied, designates_object, is_null_pointer_constant,
    is_type_name_text, is_volatile_read_in, names_a_type, typedef_is_volatile, typedef_read_in,
    EffectInputs, EffectTable, FileScope, Proof, PURE_BUILTINS,
};
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::library_effects::{library_call_effect, LibraryEffect};
use crate::utility::cert_c::std_functions;
use lang_parsing_substrate::query;
use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tree_sitter::Node;

/// The policy option that credits the library functions the
/// `stdlib_call_effects` contract lists as free of side effects.
const PURE_LIBRARY_CALLS: &str = "pre31_listed_library_calls_pure";

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
    /// Real paths of the headers read from outside every project root
    /// (`IncludeReport::outside_headers`): a C library header's definition
    /// of `assert` is not the project replacing it.
    outside_headers: RefCell<Arc<HashSet<String>>>,
    /// Every name a `#define` or an `#undef` somewhere in the scan sets
    /// (`ProjectContext::defined_macro_names`, `undefined_macro_names`).
    set_names: RefCell<SetNames>,
    /// What calling each scanned function can change, closed over the call
    /// graph of the whole scan. `None` when no prescan context was given.
    effects: RefCell<Option<EffectView>>,
    /// Struct member and typedef types as this file sees them, for a read
    /// of a `volatile` member.
    types: RefCell<VisibleTypes>,
    /// `pre31_unknown_call_pure`, `pre31_listed_library_calls_pure` and
    /// `stdlib_call_effects` decide how a
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
            outside_headers: RefCell::new(Arc::new(HashSet::new())),
            set_names: RefCell::default(),
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
    fn reads_header_facts(&self) -> bool {
        true
    }

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
        *self.set_names.borrow_mut() = (
            Arc::clone(&context.defined_macro_names),
            Arc::clone(&context.undefined_macro_names),
        );
        *self.outside_headers.borrow_mut() = Arc::new(
            context
                .include_report
                .outside_headers
                .iter()
                .cloned()
                .collect(),
        );
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
        let arm_sites =
            macro_expand::collect_function_macro_arm_sites(&ast_utils::tree_root(node), source);
        let arms: HashMap<String, Vec<MacroArm>> = arm_sites
            .iter()
            .map(|(name, arms)| (name.clone(), arms.iter().map(|(a, _)| a.clone()).collect()))
            .collect();
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
            root: ast_utils::tree_root(node),
            names: &macro_names,
            first: &function_macros,
            arm_sites: &arm_sites,
            preproc: OnceCell::new(),
            site: Cell::new((0, 0)),
            project_arms: &project_arms,
            include_edges: &include_edges,
            file_path: file_path.as_deref(),
            include_closure: OnceCell::new(),
            aliases: &aliases,
            outside: &self.outside_macros.borrow(),
            outside_headers: &self.outside_headers.borrow(),
            set_names: &self.set_names.borrow(),
            lines: ConfiguredLines::of(source),
            effects: effects.as_ref(),
            local_table: local_table.as_ref(),
            types: &types,
            settings: &settings,
            masked: OnceCell::new(),
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
            ctx.site
                .set((call_node.start_position().row + 1, call_node.start_byte()));
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

/// The C library header whose inclusion defines `name`, one of
/// [`library_unsafe_argument`]'s.
fn library_header(name: &str) -> &'static str {
    match name {
        "assert" => "assert.h",
        "getwc" | "putwc" => "wchar.h",
        _ => "stdio.h",
    }
}

/// The names a `#define` and the names an `#undef` somewhere in the scan
/// sets.
type SetNames = (Arc<HashSet<String>>, Arc<HashSet<String>>);

/// What a function-like macro name stands for at an invocation.
enum InForce {
    /// These definitions, each of which can compile with it.
    Arms(Vec<MacroArm>),
    /// The scan defines the name, but no definition can compile with it: the
    /// name is a function there.
    Undefined,
    /// No definition anyone can read.
    Unreadable,
}

/// Which definition of a C library macro is in force at an invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LibraryMacro {
    /// The library header's, as the standard specifies it.
    Library,
    /// A project header's, which replaced it.
    Project,
    /// Either: one `#include` reaches both, in an order the include graph
    /// does not record.
    Either,
}

/// How the call `name(...)` evaluates the arguments of `call`, when a paste
/// renamed `call`'s callee to `name`: once each for a function or a C
/// library macro 7.1.4 binds, and for a function-like macro by every arm
/// it has at every position `call` fills. A macro whose body nobody can
/// read proves nothing, so the argument is not credited at all.
fn pasted_call_evaluation(ctx: &Ctx, name: &str, call: &Node) -> ArgEvaluation {
    let name = ctx.resolve(name);
    if ctx.undefined_here(name) {
        return ArgEvaluation::Once;
    }
    let arms = match ctx.local_arms(name).filter(|a| !a.is_empty()) {
        Some(arms) => arms,
        None if library_unsafe_argument(name).is_some() => return ArgEvaluation::Unpredictable,
        None if ctx.bound_by_library_contract(name) || !ctx.names.contains(name) => {
            return ArgEvaluation::Once;
        }
        None => ctx.definitions(name),
    };
    if arms.is_empty() {
        return ArgEvaluation::Never;
    }
    let count = call.child_by_field_name("arguments").map_or(0, |a| {
        let mut cursor = a.walk();
        a.named_children(&mut cursor)
            .filter(|n| n.kind() != "comment")
            .count()
    });
    let forward = |inner: &str| {
        let inner = ctx.resolve(inner);
        if ctx.names.contains(inner) && !ctx.bound_by_library_contract(inner) {
            ctx.definitions(inner)
        } else {
            Vec::new()
        }
    };
    let once = (0..count).all(|k| {
        arms.iter().all(|a| {
            macro_expand::argument_evaluation_through(a, k, &forward) == ArgEvaluation::Once
        })
    });
    if once {
        ArgEvaluation::Once
    } else {
        ArgEvaluation::Unpredictable
    }
}

/// The identifier `callee` is when it is `(name)`, one identifier in
/// parentheses.
fn parenthesized_name<'t>(callee: &Node<'t>) -> Option<Node<'t>> {
    if callee.kind() != "parenthesized_expression" || callee.named_child_count() != 1 {
        return None;
    }
    callee.named_child(0).filter(|n| n.kind() == "identifier")
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
    /// The tree's root: names resolve by one descent from it
    /// ([`ast_utils::resolve_identifier_binding_in`]) rather than a
    /// `Node::parent()` climb, which costs the square of the depth per name.
    root: Node<'a>,
    names: &'a macro_expand::FunctionMacroNames<'a>,
    /// One definition per name (project-wide, this file's winning).
    first: &'a HashMap<String, FunctionMacro>,
    /// This file's definitions, every preprocessor branch, variadic and
    /// `#`/`##` arms included, with where each `#define` making one sits.
    arm_sites: &'a HashMap<String, Vec<(MacroArm, Vec<ArmSite>)>>,
    /// This file's `#if` chains, read the first time a name has several
    /// definitions of its own.
    preproc: OnceCell<PreprocArms>,
    /// The invocation being judged: its 1-based line and byte offset. Every
    /// macro an invocation expands, its arguments' included, is expanded
    /// there, so each is judged by the definitions that compile with it.
    site: Cell<(usize, usize)>,
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
    /// `Pre31C::outside_headers`.
    outside_headers: &'a HashSet<String>,
    /// `Pre31C::set_names`.
    set_names: &'a SetNames,
    /// Which of this file's lines compile under a set of macro states.
    lines: ConfiguredLines<'a>,
    /// The scan's side-effect table, as this file resolves names.
    effects: Option<&'a EffectView>,
    /// This file's own functions, closed over the scan's table.
    local_table: Option<&'a EffectTable>,
    types: &'a VisibleTypes,
    settings: &'a AnalysisSettings,
    /// `source` with literals and comments blanked, made the first time an
    /// invocation's arguments are split.
    masked: OnceCell<String>,
}

impl<'a> Ctx<'a> {
    /// The definitions a call to `name` may expand to (see
    /// [`Self::in_force`]); empty when none can compile with the invocation
    /// being judged, as when no body can be read.
    fn definitions(&self, name: &str) -> Vec<MacroArm> {
        match self.in_force(name) {
            InForce::Arms(arms) => arms,
            InForce::Undefined | InForce::Unreadable => Vec::new(),
        }
    }

    /// What a call to `name` expands to at the invocation being judged: this
    /// file's arms that can compile with it, else the arms of the headers
    /// this file includes (every arm the project has when that is unknown)
    /// that can, else the one expandable definition the project keeps. Two
    /// headers may define one name two ways; a call is compiled with the one
    /// its translation unit includes (ADR-0006). Where the file or the
    /// project defines the name and no definition can compile with the
    /// invocation, it is [`InForce::Undefined`].
    fn in_force(&self, name: &str) -> InForce {
        let local = self.local_arms(name);
        if let Some(arms) = local.as_ref().filter(|a| !a.is_empty()) {
            return InForce::Arms(arms.clone());
        }
        if self.project_arms.get(name).is_some_and(|a| !a.is_empty()) {
            let closure = if self.project_arms.get(name).is_some_and(|a| a.len() > 1) {
                self.include_closure
                    .get_or_init(|| {
                        self.file_path
                            .and_then(|path| IncludeClosure::of(self.include_edges, path))
                    })
                    .as_ref()
            } else {
                None
            };
            let line = self.site.get().0;
            let arms = macro_expand::reachable_arms_admitted(
                self.project_arms,
                name,
                closure,
                &|conditions| self.compiles_under(line, conditions),
            );
            return if arms.is_empty() {
                InForce::Undefined
            } else {
                InForce::Arms(arms)
            };
        }
        // `first` holds this file's own definitions too, which `local`
        // already judged.
        if local.is_some() {
            return InForce::Undefined;
        }
        match self.first.get(name) {
            Some(m) => InForce::Arms(vec![MacroArm::from(m)]),
            None => InForce::Unreadable,
        }
    }

    /// Whether the invocation's `line` compiles under `conditions`, the
    /// macro states a definition's `#define` sits under, reading only the
    /// states that hold alike at the definition and at the call: a name
    /// some `#define` or `#undef` in the scan sets (the definition's own
    /// name, a header's self-guard, a guard another include defines) may
    /// change between the two, so its term proves nothing and is dropped.
    /// What is left are build flags, the same in every file. A condition
    /// nothing reads (`UNREAD_CONDITION`) fixes nothing either.
    fn compiles_under(&self, line: usize, conditions: &[(String, bool)]) -> bool {
        let (defined, undefined) = self.set_names;
        let flags: Vec<(String, bool)> = conditions
            .iter()
            .filter(|(n, _)| {
                n != dead_regions::UNREAD_CONDITION
                    && !defined.contains(n)
                    && !undefined.contains(n)
            })
            .cloned()
            .collect();
        self.lines.compiles_under(line, &flags)
    }

    /// This file's own definitions of `name` that can compile with the
    /// invocation being judged (ADR-0010 D4): an arm goes when every
    /// `#define` making it is in another arm of an `#if` chain than the
    /// invocation, or under build flags the invocation's line does not
    /// compile under (`#ifdef OMIT_GET` against a call inside `#ifndef
    /// OMIT_GET`; [`Self::compiles_under`]). Positive-only: an arm goes only
    /// on that proof. `None` when the file defines no arm of `name`; empty
    /// when it defines some and none can compile with the invocation.
    fn local_arms(&self, name: &str) -> Option<Vec<MacroArm>> {
        let sites = self.arm_sites.get(name).filter(|a| !a.is_empty())?;
        let (line, at) = self.site.get();
        let chains = self
            .preproc
            .get_or_init(|| PreprocArms::collect(&self.root));
        Some(
            sites
                .iter()
                .filter(|(_, defines)| {
                    defines.iter().any(|d| {
                        !chains.exclusive(d.offset, at) && self.compiles_under(line, &d.conditions)
                    })
                })
                .map(|(a, _)| a.clone())
                .collect(),
        )
    }

    /// Whether `name` is a function-like macro somewhere in the scan, but no
    /// definition of it can compile with the invocation being judged
    /// ([`InForce::Undefined`]): there the name is a function, and a call
    /// evaluates each argument once. sqlite's `sqlite3UpsertNew` is the null
    /// macro only under `SQLITE_OMIT_UPSERT`, and upsert.c compiles only
    /// without it. Never for a C library macro the standard lets evaluate an
    /// argument other than once: its header's own definition is still in
    /// force.
    fn undefined_here(&self, name: &str) -> bool {
        library_unsafe_argument(name).is_none() && matches!(self.in_force(name), InForce::Undefined)
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

    /// Which definition of `name`, a C library macro the standard lets
    /// evaluate an argument other than once, is in force at the invocation
    /// being judged, by the file's own `#include` lines before it, in order
    /// (ADR-0006, ADR-0010), and the definitions of the replacing headers
    /// those reach. A project header that defines `name` in every build
    /// (valkey's serverassert.h does `#undef assert` and defines its own)
    /// replaces the library's for what follows; `<assert.h>` reached again
    /// afterwards defines `assert` anew (C11 7.2p1), while the other library
    /// headers are included once. A header the replacing one includes is
    /// taken to come before its definition. An `#include` some builds skip
    /// (under `#ifdef USE_MYASSERT`) changes the definition only in the
    /// builds that take it, so where it would change it, either is in force;
    /// a conditional holding the invocation in the same arm skips no build
    /// of it. Without the file's include edges, or with no replacing header, the
    /// library's.
    fn library_macro_in_force(&self, name: &str) -> (LibraryMacro, Vec<MacroArm>) {
        let replacing: Vec<&ProjectMacroArm> = self
            .project_arms
            .get(name)
            .into_iter()
            .flatten()
            .filter(|e| e.conditions.iter().any(Vec::is_empty))
            .filter(|e| e.files.iter().any(|f| !self.outside_headers.contains(f)))
            .collect();
        let replacers: HashSet<&str> = replacing
            .iter()
            .flat_map(|e| e.files.iter())
            .filter(|f| !self.outside_headers.contains(*f))
            .map(String::as_str)
            .collect();
        let Some(edges) = self
            .file_path
            .map(crate::analyze::compile_commands::real_path)
            .and_then(|f| self.include_edges.get(&f))
        else {
            return (LibraryMacro::Library, Vec::new());
        };
        if replacers.is_empty() {
            return (LibraryMacro::Library, Vec::new());
        }
        let header = library_header(name);
        let is_library_header = |path: &str| {
            path.strip_prefix(UNRESOLVED_INCLUDE).unwrap_or(path) == header
                || path.ends_with(&format!("/{header}"))
        };
        // Lines no build compiles (`#if 0`); an include there reaches nothing.
        let skipped: Vec<(usize, usize)> = lang_parsing_substrate::dead_code_ranges(self.source)
            .into_iter()
            .filter(|r| {
                matches!(
                    r.reason,
                    lang_parsing_substrate::DeadCodeReason::IfZero
                        | lang_parsing_substrate::DeadCodeReason::CppOnly
                )
            })
            .map(|r| (r.start_line, r.end_line))
            .collect();
        let (line, invocation) = self.site.get();
        let mut state = LibraryMacro::Library;
        // The replacing headers the includes so far reach, in the builds
        // where one of them is in force.
        let mut reached: HashSet<&str> = HashSet::new();
        for include in query::find_descendants_of_kind(self.root, "preproc_include") {
            let at = include.start_position().row + 1;
            if at >= line {
                break;
            }
            if skipped.iter().any(|&(s, e)| at >= s && at <= e) {
                continue;
            }
            let Some(spelled) = include.child_by_field_name("path") else {
                continue;
            };
            let spelling = get_node_text(&spelled, self.source)
                .trim_matches(|c| matches!(c, '"' | '<' | '>'))
                .to_string();
            // What the include reaches, not looking past a replacing header.
            let (mut reaches, mut reaches_library) = (HashSet::new(), false);
            if spelling.rsplit('/').next() == Some(header) && name == "assert" {
                reaches_library = true;
            } else {
                let Some(target) = edges.iter().find(|t| {
                    t.strip_prefix(UNRESOLVED_INCLUDE) == Some(spelling.as_str())
                        || t.ends_with(&format!("/{spelling}"))
                }) else {
                    continue;
                };
                let mut seen: HashSet<&str> = HashSet::new();
                let mut stack: Vec<&str> = vec![target.as_str()];
                while let Some(f) = stack.pop() {
                    if !seen.insert(f) {
                        continue;
                    }
                    if replacers.contains(f) {
                        reaches.insert(f);
                        continue;
                    }
                    if is_library_header(f) {
                        reaches_library = true;
                    }
                    stack.extend(
                        self.include_edges
                            .get(f)
                            .into_iter()
                            .flatten()
                            .map(String::as_str),
                    );
                }
            }
            let after = match (!reaches.is_empty(), reaches_library && name == "assert") {
                (true, false) => LibraryMacro::Project,
                (true, true) => LibraryMacro::Either,
                (false, true) => LibraryMacro::Library,
                (false, false) => continue,
            };
            if dead_regions::under_a_conditional_apart_from(&include, self.source, Some(invocation))
            {
                if after != state {
                    state = LibraryMacro::Either;
                }
                reached.extend(reaches);
            } else {
                state = after;
                reached = reaches;
            }
        }
        let arms = replacing
            .iter()
            .filter(|e| e.files.iter().any(|f| reached.contains(f.as_str())))
            .map(|e| e.arm.clone())
            .collect();
        (state, arms)
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

    /// The byte ranges of the arguments the invocation `call` passes, split
    /// as the preprocessor splits them (C11 6.10.3p11) rather than as the
    /// parser read the list as C. `None` when the list cannot be read as
    /// text (no `(` right after the name, or none that closes).
    fn invocation_arguments(&self, call: &Node<'a>) -> Option<Vec<std::ops::Range<usize>>> {
        let name = call.child_by_field_name("function")?;
        let masked = self
            .masked
            .get_or_init(|| crate::utility::cert_c::pp_tokens::mask_source(self.source));
        let after = name.end_byte();
        let open = after + (masked.get(after..)?.len() - masked[after..].trim_start().len());
        crate::utility::cert_c::pp_tokens::invocation_arguments(masked, open)
    }

    /// The side effect of the part of `node` inside `span`, when the parser
    /// read `node` across an argument's end (`TESTONLY( rc = ) work()` parses
    /// as `rc = work()`): an assignment or `++`/`--` whose operator is inside
    /// counts, and so does each child wholly inside; nothing past the end does.
    fn effect_within(&self, node: &Node<'a>, span: &std::ops::Range<usize>) -> Effect {
        if node.start_byte() >= span.start && node.end_byte() <= span.end {
            return self.expression_effect(node);
        }
        if node.end_byte() <= span.start || node.start_byte() >= span.end {
            return Effect::None;
        }
        let mut cursor = node.walk();
        let children: Vec<Node<'a>> = node.children(&mut cursor).collect();
        let writes = matches!(node.kind(), "assignment_expression" | "update_expression")
            && children.iter().any(|c| {
                !c.is_named()
                    && c.start_byte() >= span.start
                    && c.end_byte() <= span.end
                    && (c.kind().ends_with('=') || matches!(c.kind(), "++" | "--"))
            });
        if writes {
            return Effect::Definite;
        }
        children
            .iter()
            .filter(|c| c.is_named())
            .map(|c| self.effect_within(c, span))
            .max()
            .unwrap_or(Effect::None)
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
                if is_volatile_read_in(&self.root, node, self.source)
                    || self.reads_volatile_typedef(node)
                {
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
                    // `(name)(x)`: the parser reads a cast of a parenthesized
                    // operand, `(u32) (a + b)`, as a call through `(u32)`.
                    // A type there casts and calls nothing; any other name
                    // is the call it spells, `(getc)(fp)` the function that
                    // the parentheses keep a macro from expanding. Through a
                    // pointer or a member: nothing names the body, and the
                    // callee expression may itself have effects.
                    Some(f) => match parenthesized_name(&f) {
                        Some(inner) => self.parenthesized_callee_effect(&inner, arguments.as_ref()),
                        None => self.expression_effect(&f).max(Effect::Unknown),
                    },
                    None => Effect::Unknown,
                };
                let args = arguments.map_or(Effect::None, |a| self.children_effect(&a));
                callee.max(args)
            }
            _ => self.children_effect(node),
        }
    }

    /// What `(name)(...)` can change, `inner` the identifier in the
    /// parentheses: the parser reads a cast of a parenthesized operand,
    /// `(u32) (a + b)`, as a call through `(u32)`. Resolved by declaration,
    /// in this order (ADR-0006): a name bound to an object is a call through
    /// a pointer; a function this file declares or the scan defines is that
    /// function (the parentheses keep a function-like macro of the name from
    /// expanding, C11 7.1.4p1, so `(getc)(fp)` calls getc); a typedef this
    /// file or the scan declares, a type keyword, or an object-like macro
    /// naming one is a cast and calls nothing. A name ending in `_t` that
    /// nothing declares is not taken for a type here: the call stays as
    /// unknown as any other.
    fn parenthesized_callee_effect(
        &self,
        inner: &Node<'a>,
        arguments: Option<&Node<'a>>,
    ) -> Effect {
        if designates_object(inner, self.source) {
            return Effect::Unknown;
        }
        let name = get_node_text(inner, self.source);
        let declared_function =
            ast_utils::resolve_identifier_binding(inner, name, self.source).is_some();
        if declared_function || self.function_effect(name, arguments).is_some() {
            return self.function_call_effect(name, arguments);
        }
        let no_typedefs = HashMap::new();
        let typedefs = self.effects.map_or(&no_typedefs, |v| &*v.names.typedefs);
        if self.types.typedef_types.contains_key(name)
            || typedefs.contains_key(name)
            || is_type_name_text(resolve_macro_alias(self.aliases, name))
        {
            return Effect::None;
        }
        self.function_call_effect(name, arguments)
    }

    /// [`Self::call_effect`] for a call that reaches the function itself,
    /// never a function-like macro of its name: the scanned function's
    /// effect, else the library contract, else unknown. An object-like
    /// macro still renames the callee.
    fn function_call_effect(&self, name: &str, arguments: Option<&Node<'a>>) -> Effect {
        let name = if self.names.contains(name) {
            name
        } else {
            resolve_macro_alias(self.aliases, name)
        };
        self.function_effect(name, arguments)
            .unwrap_or_else(|| self.library_effect(name))
    }

    /// Whether an identifier reads an object whose typedef is volatile
    /// (`typedef volatile uint32_t reg_t;`, usually in a header).
    fn reads_volatile_typedef(&self, ident: &Node<'a>) -> bool {
        let Some(view) = self.effects else {
            return false;
        };
        typedef_read_in(&self.root, ident, self.source)
            .is_some_and(|t| typedef_is_volatile(&t, &view.names))
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
        if ast_utils::resolve_identifier_binding_in(&self.root, ident, name, self.source).is_some()
        {
            return Effect::None;
        }
        // An identifier in the argument is not a call: only what the project
        // shows it to be (a volatile object, a macro that calls or writes)
        // counts, and a name nothing knows reads nothing here.
        match view.name_effects(name, false).proof_crediting(
            self.settings.flag("stdlib_call_effects"),
            self.settings.flag(PURE_LIBRARY_CALLS),
        ) {
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
                ast_utils::resolve_identifier_declared_type_in(&self.root, node, name, self.source)
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
        self.library_effect(name)
    }

    /// What a call to `name`, which the scan does not define, can change:
    /// the C library's contract for it where the policy reads one, else
    /// unknown.
    fn library_effect(&self, name: &str) -> Effect {
        // A POSIX-only function's contract holds only where POSIX does.
        let stdlib_contract = self.settings.flag("stdlib_call_effects")
            && (!crate::utility::cert_c::std_functions::is_posix_only_function(name)
                || self.settings.posix_holds_project());
        if stdlib_contract {
            match library_call_effect(name) {
                // Listed free of side effects: pure only where the policy
                // credits the list; otherwise as unknown as any callee.
                Some(LibraryEffect::Pure) if self.settings.flag(PURE_LIBRARY_CALLS) => {
                    return Effect::None
                }
                Some(LibraryEffect::Pure) => return Effect::Unknown,
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
        closed.map(|closed| {
            match closed
                .past_null_arguments(null)
                .proof_crediting(stdlib_contract, self.settings.flag(PURE_LIBRARY_CALLS))
            {
                Proof::Pure => Effect::None,
                Proof::Unproven => Effect::Unknown,
                Proof::Impure => Effect::Definite,
            }
        })
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
        // No definition compiles with this invocation: here it is a call.
        if ctx.undefined_here(macro_name) {
            return;
        }
        // An empty set of this file's own arms falls through to the library
        // reading and the project's definitions.
        let arms = ctx.local_arms(macro_name).filter(|a| !a.is_empty());

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
        let evaluates_once = move |a: &MacroArm, i, pasting: Pasting<'_>| {
            macro_expand::argument_evaluation_pasting(a, i, &forward, pasting)
                == ArgEvaluation::Once
        };
        let unsafe_at: Box<dyn Fn(usize, Pasting<'_>) -> bool + '_> = if let Some(arms) = arms {
            let arms = arms.clone();
            Box::new(move |i, p| arms.iter().any(|a| !evaluates_once(a, i, p)))
        } else if let Some(k) = library_unsafe_argument(macro_name) {
            // The definition in force here, not the name (ADR-0006).
            match ctx.library_macro_in_force(macro_name) {
                (LibraryMacro::Library, _) => Box::new(move |i, _| i == k),
                (LibraryMacro::Project, arms) => {
                    Box::new(move |i, p| arms.iter().any(|a| !evaluates_once(a, i, p)))
                }
                (LibraryMacro::Either, arms) => {
                    Box::new(move |i, p| i == k || arms.iter().any(|a| !evaluates_once(a, i, p)))
                }
            }
        } else if ctx.bound_by_library_contract(macro_name) {
            // The implementation's macro for a library function: whatever
            // its body looks like, C11 7.1.4 has it evaluate each argument
            // once (glibc's tolower reads `c` twice through __tobody).
            return;
        } else if ctx.names.contains(macro_name) {
            let defs = ctx.definitions(macro_name);
            if defs.is_empty() {
                Box::new(|_, _| true)
            } else {
                Box::new(move |i, p| defs.iter().any(|a| !evaluates_once(a, i, p)))
            }
        } else {
            return;
        };

        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        let parsed: Vec<Node> = arguments
            .named_children(&mut cursor)
            .filter(|a| a.kind() != "comment")
            .collect();
        // What the macro receives is the preprocessor's split of the list;
        // the parser's nodes only say what each argument's text holds.
        let spans: Vec<std::ops::Range<usize>> = ctx
            .invocation_arguments(node)
            .unwrap_or_else(|| parsed.iter().map(|a| a.byte_range()).collect());
        for (i, span) in spans.iter().enumerate() {
            let inside: Vec<&Node> = parsed
                .iter()
                .filter(|a| a.start_byte() < span.end && a.end_byte() > span.start)
                .collect();
            let whole = match inside.as_slice() {
                [arg] if arg.byte_range() == *span => Some(**arg),
                _ => None,
            };
            // `prefix ## CALL` pastes only a call's name; its argument list
            // stays, evaluated as the pasted name evaluates it.
            let callee = whole.and_then(|arg| {
                arg.child_by_field_name("function")
                    .filter(|f| arg.kind() == "call_expression" && f.kind() == "identifier")
            });
            let judge = |name: &str| match whole {
                Some(arg) => pasted_call_evaluation(ctx, name, &arg),
                None => ArgEvaluation::Unpredictable,
            };
            let pasting = match callee {
                Some(f) => Pasting::CallKeepsArguments {
                    callee: get_node_text(&f, ctx.source),
                    judge: &judge,
                },
                None => Pasting::ConsumesArgument,
            };
            if !unsafe_at(i, pasting) {
                continue;
            }
            let effect = match whole {
                Some(arg) => ctx.expression_effect(&arg),
                None => inside
                    .iter()
                    .map(|a| ctx.effect_within(a, span))
                    .max()
                    .unwrap_or(Effect::None),
            };
            if !ctx.reported(effect) {
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
                    ctx.source[span.clone()].trim()
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
