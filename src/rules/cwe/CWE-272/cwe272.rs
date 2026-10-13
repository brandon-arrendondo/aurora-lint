// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CWE-272: Least privilege violation
//!
//! Detects a registry write under a root key only an administrator may
//! write: `HKEY_LOCAL_MACHINE` or `HKEY_CLASSES_ROOT` handed to a call that
//! creates, sets or deletes a key or value, or that opens the key with a
//! write right in its access mask (`registry_access`). A read there needs no
//! elevated rights, so `RegOpenKeyExA(HKEY_LOCAL_MACHINE, ..., KEY_READ, ...)`
//! is not a finding. The Shell's `SHRegCreateUSKey` with `SHREGSET_HKLM` and
//! `SHRegOpenUSKey` with `fIgnoreHKCU` set and a write mask are the same
//! write.
//!
//! The registry check follows the root-key handle through project wrappers:
//! `SetRegValue(HKEY_LOCAL_MACHINE, ...)` whose body forwards its first
//! parameter to `RegCreateKeyExA` is the same HKLM write as the direct call.
//! The walk is bounded and follows `FunctionSummary::param_passthroughs` for
//! function hops and `macro_forwarding_target` for a function-like macro hop;
//! at each function it asks `FunctionSummary::registry_write_root_params`
//! whether that body hands the parameter to a registry call that writes. So a
//! chain like ventoy's `ReadRegistryKey32(root, key)` -> `GetRegistryKey32`
//! (macro) -> `_GetRegistryKey(key_root, ...)` is reported when
//! `_GetRegistryKey` opens `key_root` with a write right on some path, and
//! not when every open there is a read. The argument itself is resolved
//! through object-like aliases (`#define REGKEY_HKLM HKEY_LOCAL_MACHINE`)
//! the same way.

use super::super::{CertRule, RuleViolation};
use crate::analyze::check_macros::{MacroDefinition, ObjectMacroTimeline};
use crate::analyze::context::ScopedTable;
use crate::analyze::context::{IncludeClosure, ProjectContext};
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::macro_expand::{macro_forwarding_target, FunctionMacro};
use crate::analyze::noreturn::{callee_spelling, library_function_replaced_in_every_build};
use crate::analyze::side_effects::designates_object;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::call_roles::is_win32_api;
use crate::utility::cert_c::registry_access::{self, RegistryAccess};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tree_sitter::Node;

/// `SHRegCreateUSKey`: the flags argument (index 4) selects HKLM.
const SHREG_CREATE: &str = "SHRegCreateUSKey";

/// `SHRegCreateUSKey` flags that write the key under HKLM.
const SHREG_HKLM_FLAGS: &[&str] = &["SHREGSET_HKLM", "SHREGSET_FORCE_HKLM"];

/// `SHRegOpenUSKey`: fIgnoreHKCU=TRUE (index 4) means HKLM, and the access
/// mask is index 1.
const SHREG_OPEN: &str = "SHRegOpenUSKey";

/// How many wrapper hops to follow from the call site before giving up. A
/// function hop and a macro hop each count as one; ventoy's deepest chain
/// (function -> macro -> function -> `RegOpenKeyExA`) needs three.
const MAX_WRAPPER_DEPTH: usize = 4;

/// Object-like replacement lists by name, each distinct body once, sorted:
/// the same answer whatever order the definitions were read in.
type MacroBodies = HashMap<String, Vec<String>>;

/// The object-like macros a scanned file sees, for reading a root key or an
/// access mask spelled as a macro (`#define ROOT (HKEY_LOCAL_MACHINE)`,
/// `#define M (KEY_READ | KEY_SET_VALUE)`, `#define REGKEY_HKLM
/// HKEY_LOCAL_MACHINE`).
///
/// At a call, a name means what the file's own `#define`s and `#undef`s
/// before that line leave in force ([`ObjectMacroTimeline`]): a sequential
/// redefinition replaces the earlier body, and only `#if` arms are build
/// alternatives. Where some build reaches the call with none of the file's
/// own directives applying, the definitions of the headers the file can
/// reach stand ([`IncludeClosure`], as `library_macro_replaces` scopes a
/// macro), each header read for what it leaves in force: an unrelated
/// header's definition of the same name is another build's or another
/// program's. The headers are read once per scanned file, and only when a
/// name is not settled sooner, which the Win32 mask and root-key names
/// always are.
///
/// **Limitation:** where an `#include` line falls is not read: a header's
/// definitions are taken as standing before the file's own directives, so a
/// header included after the file redefines a name is read as replaced.
///
/// When the definitions that apply disagree, each is a build where the name
/// means that body: a mask is a write if one of them writes and a root key
/// privileged if one of them is (ADR-0010 D1, `registry_access::reaches`).
struct FileMacros<'r> {
    /// This file's own directives.
    own: ObjectMacroTimeline,
    /// The reachable headers' definitions, read on the first name the file
    /// leaves to them.
    reachable: std::cell::OnceCell<MacroBodies>,
    /// Reads `reachable`.
    load: Box<dyn Fn() -> MacroBodies + 'r>,
}

impl FileMacros<'_> {
    /// Every body `name` may stand for on `line`.
    fn bodies_at(&self, name: &str, line: usize) -> Vec<String> {
        let in_force = self.own.in_force(name, line);
        let mut bodies = in_force.bodies;
        if in_force.inherits {
            if let Some(inherited) = self.reachable.get_or_init(|| (self.load)()).get(name) {
                bodies.extend(inherited.iter().cloned());
                bodies.sort();
                bodies.dedup();
            }
        }
        bodies
    }
}

/// Add what the file `source` leaves each object-like name standing for to
/// `into`, each distinct body once, kept sorted.
fn add_bodies_left_in_force(into: &mut MacroBodies, source: &str) {
    let timeline = ObjectMacroTimeline::of(source);
    for name in timeline.names() {
        let in_force = timeline.in_force(name, usize::MAX);
        if in_force.bodies.is_empty() {
            continue;
        }
        let bodies = into.entry(name.clone()).or_default();
        bodies.extend(in_force.bodies);
        bodies.sort();
        bodies.dedup();
    }
}

/// The CWE-272 checker.
pub struct Cwe272 {
    /// Prescan function summaries: `param_passthroughs` is the edge a wrapper
    /// hop follows and `registry_write_root_params` the answer at each hop
    /// (handle from `set_project_context`, see the catalog's "Cross-file
    /// project context" section).
    function_summaries: RefCell<ScopedTable<FunctionSummary>>,
    /// Project function-like macros, for a forwarding-macro hop.
    function_macros: RefCell<Arc<HashMap<String, FunctionMacro>>>,
    /// The prescan's macro tables, for whether a Win32 name is replaced by a
    /// macro in this file (`library_function_replaced_in_every_build`).
    project: RefCell<Option<ProjectContext>>,
    /// The file being checked, for the headers it includes.
    file_path: RefCell<Option<PathBuf>>,
}

impl Default for Cwe272 {
    fn default() -> Self {
        Self::new()
    }
}

impl Cwe272 {
    /// The checker, with no project context yet.
    pub fn new() -> Self {
        Self {
            function_summaries: RefCell::default(),
            function_macros: RefCell::new(Arc::new(HashMap::new())),
            project: RefCell::new(None),
            file_path: RefCell::new(None),
        }
    }

    /// Whether the project gives a Win32 name a meaning of its own for a
    /// call from any file: it defines a function by that name with EXTERNAL
    /// linkage that every build compiles (no `#if` arm constrains the
    /// definition), or an object-like project macro of that name replaces it
    /// in every configuration. Another file's `static` definition is that
    /// file's alone, and a definition only some builds compile (under
    /// `#ifdef _WIN32_WCE`) leaves the Win32 API in the others (ADR-0006,
    /// ADR-0010). A hop asks this of the call a wrapper body made, which is
    /// all that is known of another file; the scanned file's own definitions
    /// and macros are `library_replaced_here`'s.
    fn project_replaces(&self, name: &str) -> bool {
        let defined_everywhere = self.function_summaries.borrow().get(name).is_some_and(|s| {
            s.definitions
                .iter()
                .any(|d| !d.internal_linkage && d.arms.is_empty())
        });
        if defined_everywhere {
            return true;
        }
        let project = self.project.borrow();
        let Some(project) = project.as_ref() else {
            return false;
        };
        !project.macros_defined_outside_project.contains(name)
            && !project.conditional_macro_names.contains(name)
            && project.macro_definitions.get(name).is_some_and(|defs| {
                defs.iter()
                    .any(|def| matches!(def, MacroDefinition::Object { .. }))
            })
    }

    /// Whether `name`, a Win32 API's, means something else for a call in this
    /// file (ADR-0006): the project defines or replaces it
    /// (`project_replaces`), or this file does
    /// (`library_function_replaced_in_every_build`: its own definition or
    /// `static` declaration that every build compiles, or a macro reaching
    /// it).
    fn library_replaced_here(&self, root: &Node, source: &str, name: &str) -> bool {
        self.project_replaces(name)
            || library_function_replaced_in_every_build(
                root,
                source,
                name,
                self.project.borrow().as_ref(),
                self.file_path.borrow().as_deref(),
            )
    }

    /// What each object-like macro stands for in the headers the checked file
    /// can reach, itself excluded: its include closure as the prescan
    /// resolved it (the closure `library_macro_replaces` reads). With no
    /// file path, nothing says which headers the file sees, so the project's
    /// every definition applies.
    fn reachable_bodies(&self) -> MacroBodies {
        let mut bodies = MacroBodies::new();
        let project = self.project.borrow();
        let Some(project) = project.as_ref() else {
            return bodies;
        };
        let file_path = self.file_path.borrow();
        let Some(path) = file_path.as_deref() else {
            for (name, defs) in project.macro_definitions.iter() {
                for def in defs {
                    if let MacroDefinition::Object { body } = def {
                        bodies.entry(name.clone()).or_default().push(body.clone());
                    }
                }
            }
            for list in bodies.values_mut() {
                list.sort();
                list.dedup();
            }
            return bodies;
        };
        let closure = IncludeClosure::of(&project.include_edges, path).unwrap_or_default();
        let own = std::fs::canonicalize(path)
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        let mut files: Vec<&String> = closure
            .files
            .iter()
            .filter(|f| Some(*f) != own.as_ref())
            .collect();
        files.sort();
        for file in files {
            if let Ok(text) = std::fs::read_to_string(file) {
                add_bodies_left_in_force(&mut bodies, &text);
            }
        }
        bodies
    }

    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let macros = FileMacros {
            own: ObjectMacroTimeline::of(source),
            reachable: std::cell::OnceCell::new(),
            load: Box::new(|| self.reachable_bodies()),
        };
        let mut replaced: HashMap<String, bool> = HashMap::new();
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_call(&call, node, source, &macros, &mut replaced, violations);
        }
    }

    /// Does argument `arg_idx` of a call to `callee` reach the root-key
    /// argument of a registry call that writes, within `MAX_WRAPPER_DEPTH`
    /// hops? Returns that registry call's name. A project function answers
    /// from its summary (`registry_write_root_params`, then its
    /// `param_passthroughs`: MAY-forward, a wrapper that writes the key only
    /// on some path still writes it); a name the project does not define
    /// answers from `registry_access`'s rows, where only a call that writes
    /// by what it is counts, because a hop never sees the mask the forwarded
    /// call passes. A macro hop follows `macro_forwarding_target`'s
    /// positional map. `active` breaks cycles.
    fn write_sink(
        &self,
        callee: &str,
        arg_idx: usize,
        depth: usize,
        active: &mut HashSet<String>,
    ) -> Option<String> {
        if depth >= MAX_WRAPPER_DEPTH || !active.insert(callee.to_string()) {
            return None;
        }
        let mut found = None;
        if let Some(summary) = self.function_summaries.borrow().get(callee) {
            // The body's registry call is the Win32 one unless the project
            // gives that name its own meaning; then its own function is
            // followed through `param_passthroughs` instead.
            found = summary
                .registry_write_root_params
                .get(&arg_idx)
                .filter(|call| !self.project_replaces(call))
                .cloned();
            if found.is_none() {
                if let Some(edges) = summary.param_passthroughs.get(&arg_idx) {
                    for (next, next_idx) in edges {
                        found = self.write_sink(next, *next_idx, depth + 1, active);
                        if found.is_some() {
                            break;
                        }
                    }
                }
            }
        } else if let Some(access) = registry_access::root_key_call(callee) {
            found = (arg_idx == registry_access::ROOT_KEY_ARG
                && access == RegistryAccess::Writes
                && !self.project_replaces(callee))
            .then(|| callee.to_string());
        } else if let Some((next, param_map)) =
            macro_forwarding_target(&self.function_macros.borrow(), callee)
        {
            for (next_idx, mapped) in param_map.iter().enumerate() {
                if *mapped == Some(arg_idx) {
                    found = self.write_sink(&next, next_idx, depth + 1, active);
                    if found.is_some() {
                        break;
                    }
                }
            }
        }
        active.remove(callee);
        found
    }

    fn check_call(
        &self,
        node: &Node,
        root: &Node,
        source: &str,
        macros: &FileMacros<'_>,
        replaced: &mut HashMap<String, bool>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Only a registry API, a project function or a function-like macro
        // can reach a registry write; the spelling settles that before the
        // costlier question of what the callee binds.
        let Some((callee, func_name)) = callee_spelling(node, source) else {
            return;
        };
        let may_reach = registry_access::root_key_call(&func_name).is_some()
            || is_win32_api(&func_name, SHREG_CREATE)
            || is_win32_api(&func_name, SHREG_OPEN)
            || self.function_summaries.borrow().contains_key(&func_name)
            || self.function_macros.borrow().contains_key(&func_name);
        // The callee as a function: a local or parameter of a Win32 name (a
        // function pointer) is not the API, nor a project function (ADR-0006).
        if !may_reach || designates_object(&callee, source) {
            return;
        }
        let args = match node.child_by_field_name("arguments") {
            Some(a) => a,
            None => return,
        };
        let arg_nodes: Vec<Node> = (0..args.child_count())
            .filter_map(|i| args.child(i))
            .filter(|c| !matches!(c.kind(), "(" | ")" | "," | "comment"))
            .collect();
        let arg_texts: Vec<&str> = arg_nodes
            .iter()
            .map(|a| get_node_text(a, source).trim())
            .collect();
        // A mask term or root key may be a macro: an alias of another name
        // (`#define APP_ACCESS KEY_WRITE`) or a replacement list, as the
        // definitions in force at the call give it.
        let line = node.start_position().row + 1;
        let expand = |t: &str| macros.bodies_at(t, line);
        let writes = |mask: &str| registry_access::mask_requests_write(mask, &expand);
        // A Win32 name is the API unless the project or this file gives it a
        // meaning of its own; asked only of a name with a row.
        let is_win32_row = registry_access::root_key_call(&func_name).is_some()
            || is_win32_api(&func_name, SHREG_CREATE)
            || is_win32_api(&func_name, SHREG_OPEN);
        let replaced = is_win32_row
            && *replaced
                .entry(func_name.clone())
                .or_insert_with(|| self.library_replaced_here(root, source, &func_name));
        let has_summary = self.function_summaries.borrow().get(&func_name).is_some();

        // A registry call -- or a project wrapper around one -- handed a
        // privileged root key. Every argument position is a candidate: a
        // wrapper is free to take the root key anywhere in its own signature.
        for (arg_idx, arg) in arg_nodes.iter().enumerate() {
            // Where the argument would be written under, asked before what
            // the argument is: most calls reach no registry write at all.
            let sink = match registry_access::root_key_call(&func_name) {
                // The Win32 call itself: its own mask is in view here.
                Some(access) if !replaced => {
                    if arg_idx != registry_access::ROOT_KEY_ARG {
                        continue;
                    }
                    Err(access)
                }
                // Replaced by a macro or definition with no summary to
                // follow: nothing is known of what it does.
                Some(_) if !has_summary => continue,
                _ => match self.write_sink(&func_name, arg_idx, 0, &mut HashSet::new()) {
                    Some(sink) => Ok(sink),
                    None => continue,
                },
            };
            // Through casts, parentheses and macros:
            // `(HKEY)(HKEY_LOCAL_MACHINE)` and `ROOT` are the key.
            let Some(resolved) = registry_access::privileged_root_key(arg_texts[arg_idx], &expand)
            else {
                continue;
            };
            let sink = match sink {
                Ok(sink) => Some(sink),
                Err(access) => registry_access::call_writes(access, &arg_texts, &expand)
                    .then(|| func_name.clone()),
            };
            if let Some(sink) = sink {
                let via = if sink == func_name {
                    String::new()
                } else {
                    format!(" (passed through to '{}')", sink)
                };
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Registry operation '{}' writes under '{}'{}, which requires \
                         administrator privileges. Write per-user settings under \
                         HKEY_CURRENT_USER to follow least privilege.",
                        func_name, resolved, via
                    ),
                    file_path: String::new(),
                    line: arg.start_position().row + 1,
                    column: arg.start_position().column + 1,
                    suggestion: Some(format!("Use HKEY_CURRENT_USER instead of {}", resolved)),
                    ..Default::default()
                });
                // One finding per call, however many hops it took.
                break;
            }
        }

        // SHRegCreateUSKey with an HKLM flag (5th argument, index 4) creates
        // the key there.
        if is_win32_api(&func_name, SHREG_CREATE) && !replaced {
            if let Some(flag_arg) = arg_nodes.get(4) {
                let hklm = |t: &str| SHREG_HKLM_FLAGS.contains(&t);
                if let Some(flag) = registry_access::reaches(arg_texts[4], &expand, &hklm) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!(
                            "Registry operation '{}' uses {} which writes under \
                             HKEY_LOCAL_MACHINE. Use SHREGSET_HKCU to follow least privilege.",
                            func_name, flag
                        ),
                        file_path: String::new(),
                        line: flag_arg.start_position().row + 1,
                        column: flag_arg.start_position().column + 1,
                        suggestion: Some("Use SHREGSET_HKCU instead of SHREGSET_HKLM".to_string()),
                        ..Default::default()
                    });
                }
            }
        }

        // SHRegOpenUSKey with fIgnoreHKCU=TRUE (5th argument, index 4) opens
        // the HKLM key; a write mask (2nd argument) makes it a write.
        if is_win32_api(&func_name, SHREG_OPEN) && !replaced {
            if let (Some(flag_arg), Some(mask)) = (arg_nodes.get(4), arg_texts.get(1)) {
                let set = |t: &str| matches!(t, "TRUE" | "true" | "1");
                if registry_access::reaches(arg_texts[4], &expand, &set).is_some() && writes(mask) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!(
                            "Registry operation '{}' with fIgnoreHKCU=TRUE opens \
                             HKEY_LOCAL_MACHINE for writing. Set it to FALSE to follow \
                             least privilege.",
                            func_name
                        ),
                        file_path: String::new(),
                        line: flag_arg.start_position().row + 1,
                        column: flag_arg.start_position().column + 1,
                        suggestion: Some(
                            "Set fIgnoreHKCU to FALSE to use HKEY_CURRENT_USER".to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }
}

impl CertRule for Cwe272 {
    fn rule_id(&self) -> &'static str {
        "CWE-272"
    }

    fn description(&self) -> &'static str {
        "Do not write registry keys that need administrator rights when a per-user key would do"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "CWE-272"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }

    fn set_file_path(&self, path: &std::path::Path) {
        *self.file_path.borrow_mut() = Some(path.to_path_buf());
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.clone());
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.function_macros.borrow_mut() = context.function_macros.clone();
    }
}
