// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! FIO21-C: Do not create temporary files in shared directories
//!
//! ## Detection Strategy
//! The ruled forms (FIO21-C/2026-10-07/disposition):
//! - (a) any call to `tmpnam`, `tempnam`, `mktemp` or `tmpfile`;
//! - (b) a call that creates a file, `fopen` in a `w` or `a` mode or
//!   `open`/`openat` with `O_CREAT`, whose path is a literal under a shared
//!   directory (`/tmp/`, `/var/tmp/`, `P_tmpdir`) or a result of form (a).
//!
//! A callee is the function its spelling resolves to, never the spelling
//! itself: through object-like aliases in any live definition (Juliet's
//! `#define TMPNAM tmpnam`, accusing per ADR-0010 D1), through every live
//! definition of a function-like macro (`macro_expand`), and not when the
//! name designates an object or the file defines a function of that name
//! (ADR-0006). A path argument is judged by its value, never its spelling:
//! a literal, a call of form (a), or a variable whose last write before the
//! open, resolved to the same declaration, is one of those (`tmpnam(buf)`
//! and `mktemp(buf)` write the name into `buf`). An open that creates nothing
//! is not reported.
//!
//! ## Presets
//! - Strict and pedantic report every form as CERT's page is written.
//! - The default policy does not report `tmpfile` where POSIX holds, since
//!   POSIX removes the file it creates: the option
//!   `fio21_tmpfile_exempt_under_posix` (FIO21-C/2026-10-07/presets).

use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval;
use crate::analyze::context::ProjectContext;
use crate::analyze::macro_expand::{self, FunctionMacro};
use crate::analyze::noreturn::{callee_spelling, library_names_redefined_among};
use crate::analyze::side_effects::designates_object;
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::{get_node_text, resolve_identifier_declarator};
use crate::utility::cert_c::node_children::NodeChildren;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

/// The option that withholds a report on `tmpfile` where POSIX holds
/// (`settings::OPTIONS`).
const TMPFILE_OPTION: &str = "fio21_tmpfile_exempt_under_posix";

/// How many function-like macros deep an invocation is expanded.
const MAX_MACRO_DEPTH: usize = 4;

/// The shared directories a literal path may begin with.
const SHARED_DIRECTORIES: &[&str] = &["/tmp/", "/var/tmp/"];

pub struct Fio21C {
    project_aliases: RefCell<Arc<HashMap<String, String>>>,
    /// Every live target of each project alias, for the names an alias
    /// reaches in some build.
    project_alias_alternatives: RefCell<Arc<HashMap<String, Vec<String>>>>,
    project_function_macros: RefCell<Arc<HashMap<String, FunctionMacro>>>,
    settings: RefCell<Arc<AnalysisSettings>>,
}

impl Fio21C {
    pub fn new() -> Self {
        Self {
            project_aliases: RefCell::new(Arc::new(HashMap::new())),
            project_alias_alternatives: RefCell::new(Arc::new(HashMap::new())),
            project_function_macros: RefCell::new(Arc::new(HashMap::new())),
            settings: RefCell::new(Arc::new(AnalysisSettings::default())),
        }
    }
}

impl Default for Fio21C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Fio21C {
    fn reads_header_facts(&self) -> bool {
        true
    }

    fn rule_id(&self) -> &'static str {
        "FIO21-C"
    }

    fn description(&self) -> &'static str {
        "Do not create temporary files in shared directories"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "FIO21-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_aliases.borrow_mut() = context.macro_aliases.clone();
        *self.project_alias_alternatives.borrow_mut() = context.macro_alias_alternatives.clone();
        *self.project_function_macros.borrow_mut() = context.function_macros.clone();
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        *self.settings.borrow_mut() = Arc::clone(settings);
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut aliases =
            const_eval::merged_macro_aliases(&self.project_aliases.borrow(), node, source);
        // An alias defined more than one way reaches a callee this rule
        // looks for if any live definition does (ADR-0010 D1).
        let alternatives = const_eval::merged_macro_alias_alternatives(
            &self.project_alias_alternatives.borrow(),
            node,
            source,
        );
        const_eval::with_accusing_alias_targets(&mut aliases, &alternatives, |t| {
            Callee::library(t).is_some()
        });
        let settings = self.settings.borrow();
        let file = FileContext {
            aliases,
            local_macros: macro_expand::collect_function_macros(node, source),
            project_macros: Arc::clone(&self.project_function_macros.borrow()),
            redefined: library_names_redefined_among(node, source, |n| {
                Callee::library(n).is_some()
            }),
            string_macros: const_eval::collect_string_literal_macros(node, source),
            tmpfile_reported: !(settings.flag(TMPFILE_OPTION) && settings.posix_holds_project()),
            reaches: RefCell::new(HashMap::new()),
        };

        let mut violations = Vec::new();
        let mut lines = HashSet::new();
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            let Some(finding) = file.finding_at(&call, source) else {
                continue;
            };
            let position = call.start_position();
            // One report per line: an open whose path is `tmpnam(NULL)` is
            // both forms at one site.
            if !lines.insert(position.row) {
                continue;
            }
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                line: position.row + 1,
                column: position.column + 1,
                file_path: String::new(),
                message: finding.message(),
                suggestion: Some(
                    "Create the file with mkstemp() in a directory only this program's user can \
                     write (FIO15-C)"
                        .to_string(),
                ),
                requires_manual_review: None,
            });
        }
        violations
    }
}

/// A library function this rule judges a call of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Callee {
    /// `tmpnam`, `tempnam` or `mktemp`: produces a file name and creates
    /// nothing.
    TempName(&'static str),
    Tmpfile,
    Fopen,
    Open,
    Openat,
}

impl Callee {
    /// The function `name` is. The large-file names are the same functions:
    /// glibc's headers rename each call to them (`#define tmpfile
    /// tmpfile64`) when a build sets `_FILE_OFFSET_BITS=64`.
    fn library(name: &str) -> Option<Callee> {
        Some(match name {
            "tmpnam" => Callee::TempName("tmpnam"),
            "tempnam" => Callee::TempName("tempnam"),
            "mktemp" => Callee::TempName("mktemp"),
            "tmpfile" | "tmpfile64" => Callee::Tmpfile,
            "fopen" | "fopen64" => Callee::Fopen,
            "open" | "open64" => Callee::Open,
            "openat" | "openat64" => Callee::Openat,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Callee::TempName(n) => n,
            Callee::Tmpfile => "tmpfile",
            Callee::Fopen => "fopen",
            Callee::Open => "open",
            Callee::Openat => "openat",
        }
    }
}

/// Where a creating open's path comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PathOrigin {
    /// A literal under a shared directory, as written.
    SharedLiteral(String),
    /// The name a form (a) call produced.
    TempName(&'static str),
}

/// What one call site is.
#[derive(Debug, Clone)]
struct Finding {
    /// How the callee is written, when that is not its name: a macro or an
    /// alias.
    spelled: Option<String>,
    callee: Callee,
    /// For a creating open, where its path comes from.
    path: Option<PathOrigin>,
}

impl Finding {
    fn display(&self) -> String {
        match &self.spelled {
            Some(s) => format!("{s} (expanding to {}())", self.callee.name()),
            None => format!("{}()", self.callee.name()),
        }
    }

    fn message(&self) -> String {
        let display = self.display();
        match (&self.path, self.callee) {
            (Some(PathOrigin::SharedLiteral(path)), _) => format!(
                "{display} creates the file {path} in a shared directory, where another user of \
                 the directory can create or link that name first."
            ),
            (Some(PathOrigin::TempName(from)), _) => format!(
                "{display} creates a file at a name {from}() generated: the name is chosen in one \
                 step and the file created in another, typically in a shared directory, so \
                 another process can create or link that name first."
            ),
            (None, Callee::Tmpfile) => format!(
                "{display} creates its file in a shared directory (typically /tmp), under a name \
                 that is not portably unpredictable."
            ),
            (None, _) => format!(
                "{display} generates a temporary file name without creating the file, typically \
                 in a shared directory, so another process can create or link that name before \
                 this program opens it."
            ),
        }
    }
}

/// The invocation a macro expansion came from: its arguments as written,
/// so a path the expansion names can be judged at the call site, where its
/// declaration is.
struct Invocation<'a, 't> {
    args: Vec<(String, Node<'t>)>,
    source: &'a str,
}

impl<'t> Invocation<'_, 't> {
    /// The argument written as `text`, with the scanned file's source.
    fn argument(&self, text: &str) -> Option<(Node<'t>, &str)> {
        self.args
            .iter()
            .find(|(t, _)| t == text)
            .map(|(_, n)| (*n, self.source))
    }
}

struct FileContext {
    aliases: HashMap<String, String>,
    local_macros: HashMap<String, FunctionMacro>,
    project_macros: Arc<HashMap<String, FunctionMacro>>,
    redefined: HashSet<String>,
    string_macros: HashMap<String, String>,
    tmpfile_reported: bool,
    /// Whether a function-like macro's expansion can reach a callee of this
    /// rule, by name.
    reaches: RefCell<HashMap<String, bool>>,
}

impl FileContext {
    fn macro_definition(&self, name: &str) -> Option<&FunctionMacro> {
        self.local_macros
            .get(name)
            .or_else(|| self.project_macros.get(name))
    }

    /// Every live definition of a function-like macro.
    fn definitions(m: &FunctionMacro) -> Vec<&FunctionMacro> {
        if m.alternatives.is_empty() {
            vec![m]
        } else {
            m.alternatives.iter().flatten().collect()
        }
    }

    /// The library function `spelling` names: through every alias chain,
    /// unless the file defines a function of that name.
    fn library_callee(&self, spelling: &str) -> Option<Callee> {
        let resolved = const_eval::resolve_macro_alias(&self.aliases, spelling);
        let callee = Callee::library(resolved)?;
        (!self.redefined.contains(resolved)).then_some(callee)
    }

    /// Whether some live definition of the function-like macro `name`,
    /// through the macros its body invokes, names a callee of this rule.
    fn macro_reaches(&self, name: &str, depth: usize) -> bool {
        if let Some(known) = self.reaches.borrow().get(name) {
            return *known;
        }
        // A cycle reads as no reach until it is decided.
        self.reaches.borrow_mut().insert(name.to_string(), false);
        let reaches = self.macro_definition(name).is_some_and(|m| {
            Self::definitions(m).iter().any(|d| {
                macro_expand::body_identifiers(&d.body).iter().any(|id| {
                    self.library_callee(id).is_some()
                        || (depth < MAX_MACRO_DEPTH
                            && id != name
                            && self.macro_definition(id).is_some()
                            && self.macro_reaches(id, depth + 1))
                })
            })
        });
        self.reaches.borrow_mut().insert(name.to_string(), reaches);
        reaches
    }

    /// What `call`, in the scanned file, is.
    fn finding_at(&self, call: &Node, source: &str) -> Option<Finding> {
        let (function, spelling) = callee_spelling(call, source)?;
        if self.macro_definition(&spelling).is_some() {
            return self.macro_finding(call, &spelling, source);
        }
        let callee = self.library_callee(&spelling)?;
        // A parameter, local or function pointer spelled `tmpnam` calls
        // whatever it points at (ADR-0006).
        if designates_object(&function, source) {
            return None;
        }
        // `tmpfile` renamed to `tmpfile64` by a system header is still
        // spelled as the call is written.
        let spelled = (Callee::library(&spelling) != Some(callee)).then(|| spelling.clone());
        let path = match callee {
            Callee::TempName(_) => None,
            Callee::Tmpfile if self.tmpfile_reported => None,
            Callee::Tmpfile => return None,
            Callee::Fopen | Callee::Open | Callee::Openat => {
                Some(self.created_path(call, callee, source)?)
            }
        };
        Some(Finding {
            spelled,
            callee,
            path,
        })
    }

    /// An invocation of the function-like macro `name`, judged by what each
    /// live definition expands to with the invocation's arguments.
    fn macro_finding<'t>(&self, call: &Node<'t>, name: &str, source: &str) -> Option<Finding> {
        if !self.macro_reaches(name, 0) {
            return None;
        }
        let arguments = call.child_by_field_name("arguments")?;
        let args: Vec<(String, Node<'t>)> = arguments
            .named_child_nodes()
            .filter(|a| a.kind() != "comment")
            .map(|a| (get_node_text(&a, source).trim().to_string(), a))
            .collect();
        let texts: Vec<String> = args.iter().map(|(t, _)| t.clone()).collect();
        let frame = Invocation { args, source };
        let definition = self.macro_definition(name)?;
        for d in Self::definitions(definition) {
            // This definition alone: a macro its body invokes is judged in
            // the expansion under every one of its own definitions.
            let table = HashMap::from([(name.to_string(), d.clone())]);
            let Some(expanded) = macro_expand::expand_invocation(&table, name, &texts) else {
                continue;
            };
            let text = format!("void __sqc_fio21_expansion(void) {{ {expanded}; }}");
            let Some(tree) = parse_expansion(&text) else {
                continue;
            };
            for inner in query::find_descendants_of_kind(tree.root_node(), "call_expression") {
                if let Some(mut finding) = self.finding_in_expansion(&inner, &text, &frame, 0) {
                    finding.spelled = Some(name.to_string());
                    return Some(finding);
                }
            }
        }
        None
    }

    /// [`finding_at`](Self::finding_at) for a call inside an expansion of
    /// the invocation `frame`. `depth` counts the macros expanded inside it.
    fn finding_in_expansion<'e>(
        &self,
        call: &Node<'e>,
        text: &str,
        frame: &Invocation<'_, '_>,
        depth: usize,
    ) -> Option<Finding> {
        let (_, spelling) = callee_spelling(call, text)?;
        if self.macro_definition(&spelling).is_some() {
            // A nested invocation's arguments are expansion text, which
            // holds the outer invocation's arguments as written, so a path
            // it names is still traced back through `frame`.
            return self.nested_macro_finding(call, &spelling, text, frame, depth + 1);
        }
        let callee = self.library_callee(&spelling)?;
        let path = match callee {
            Callee::TempName(_) => None,
            Callee::Tmpfile if self.tmpfile_reported => None,
            Callee::Tmpfile => return None,
            Callee::Fopen | Callee::Open | Callee::Openat => {
                let (path, flags_or_mode) = Self::open_arguments(call, callee)?;
                if !self.creates(callee, &flags_or_mode, text, false) {
                    return None;
                }
                Some(self.expansion_path_origin(&path, text, frame)?)
            }
        };
        Some(Finding {
            spelled: None,
            callee,
            path,
        })
    }

    fn nested_macro_finding<'e>(
        &self,
        call: &Node<'e>,
        name: &str,
        text: &str,
        frame: &Invocation<'_, '_>,
        depth: usize,
    ) -> Option<Finding> {
        if depth >= MAX_MACRO_DEPTH || !self.macro_reaches(name, 0) {
            return None;
        }
        let arguments = call.child_by_field_name("arguments")?;
        let texts: Vec<String> = arguments
            .named_child_nodes()
            .filter(|a| a.kind() != "comment")
            .map(|a| get_node_text(&a, text).trim().to_string())
            .collect();
        let definition = self.macro_definition(name)?;
        for d in Self::definitions(definition) {
            let table = HashMap::from([(name.to_string(), d.clone())]);
            let Some(expanded) = macro_expand::expand_invocation(&table, name, &texts) else {
                continue;
            };
            let inner_text = format!("void __sqc_fio21_expansion(void) {{ {expanded}; }}");
            let Some(tree) = parse_expansion(&inner_text) else {
                continue;
            };
            for inner in query::find_descendants_of_kind(tree.root_node(), "call_expression") {
                if let Some(finding) = self.finding_in_expansion(&inner, &inner_text, frame, depth)
                {
                    return Some(finding);
                }
            }
        }
        None
    }

    /// The path and the flags (`open`, `openat`) or mode (`fopen`) argument
    /// of an open.
    fn open_arguments<'t>(call: &Node<'t>, callee: Callee) -> Option<(Node<'t>, Node<'t>)> {
        let arguments = call.child_by_field_name("arguments")?;
        let args: Vec<Node<'t>> = arguments
            .named_child_nodes()
            .filter(|a| a.kind() != "comment")
            .collect();
        let (path, other) = match callee {
            Callee::Openat => (1, 2),
            _ => (0, 1),
        };
        Some((*args.get(path)?, *args.get(other)?))
    }

    /// The path of an open at the call site that creates a file, judged by
    /// where its value comes from.
    fn created_path(&self, call: &Node, callee: Callee, source: &str) -> Option<PathOrigin> {
        let (path, flags_or_mode) = Self::open_arguments(call, callee)?;
        if !self.creates(callee, &flags_or_mode, source, true) {
            return None;
        }
        self.path_origin(&path, source)
    }

    /// Whether the open creates a file: `fopen` in a `w` or `a` mode,
    /// `open`/`openat` with `O_CREAT` among its flags. `traced` is set in
    /// the scanned file, whose declarations a flags variable resolves to.
    fn creates(&self, callee: Callee, arg: &Node, source: &str, traced: bool) -> bool {
        let arg = strip(*arg);
        match callee {
            Callee::Fopen => self
                .mode_text(&arg, source)
                .is_some_and(|m| m.starts_with('w') || m.starts_with('a')),
            _ => {
                if mentions_o_creat(&arg, source) {
                    return true;
                }
                // `int flags = O_WRONLY | O_CREAT; open(path, flags, 0600)`.
                traced
                    && arg.kind() == "identifier"
                    && last_value(&arg, source).is_some_and(|v| mentions_o_creat(&v, source))
            }
        }
    }

    /// An `fopen` mode written as a literal or as a macro this file defines
    /// as one.
    fn mode_text(&self, arg: &Node, source: &str) -> Option<String> {
        match arg.kind() {
            "string_literal" => Some(literal_content(arg, source)),
            "identifier" => self
                .string_macros
                .get(get_node_text(arg, source))
                .map(|raw| raw.trim_matches('"').to_string()),
            _ => None,
        }
    }

    /// Where a path argument's value comes from, in a scanned file.
    fn path_origin(&self, path: &Node, source: &str) -> Option<PathOrigin> {
        let path = strip(*path);
        if let Some(origin) = self.value_origin(&path, source) {
            return Some(origin);
        }
        if path.kind() != "identifier" {
            return None;
        }
        // A variable: its value is the last write before this use, to the
        // same declaration, or the name a form (a) call wrote into it.
        match last_definition(&path, source, |call| self.temp_name_call(call, source))? {
            Definition::Value(v) => self.value_origin(&strip(v), source),
            Definition::Filled(name) => Some(PathOrigin::TempName(name)),
        }
    }

    /// [`path_origin`](Self::path_origin) for a path in an expansion: an
    /// argument the invocation passed is judged where it was written.
    fn expansion_path_origin(
        &self,
        path: &Node,
        text: &str,
        frame: &Invocation<'_, '_>,
    ) -> Option<PathOrigin> {
        let path = strip(*path);
        if let Some(origin) = self.value_origin(&path, text) {
            return Some(origin);
        }
        let (arg, arg_source) = frame.argument(get_node_text(&path, text).trim())?;
        self.path_origin(&arg, arg_source)
    }

    /// A path value judged as written: a literal under a shared directory,
    /// or a call of form (a).
    fn value_origin(&self, value: &Node, source: &str) -> Option<PathOrigin> {
        match value.kind() {
            "string_literal" => {
                let content = literal_content(value, source);
                SHARED_DIRECTORIES
                    .iter()
                    .any(|d| content.starts_with(d))
                    .then(|| PathOrigin::SharedLiteral(format!("\"{content}\"")))
            }
            // `P_tmpdir "/name"`: <stdio.h>'s shared directory.
            "concatenated_string" => {
                let first = value.named_child(0)?;
                if first.kind() == "identifier" && get_node_text(&first, source) == "P_tmpdir" {
                    return Some(PathOrigin::SharedLiteral(
                        get_node_text(value, source).trim().to_string(),
                    ));
                }
                let content: String = value
                    .named_child_nodes()
                    .filter(|c| c.kind() == "string_literal")
                    .map(|c| literal_content(&c, source))
                    .collect();
                SHARED_DIRECTORIES
                    .iter()
                    .any(|d| content.starts_with(d))
                    .then(|| PathOrigin::SharedLiteral(format!("\"{content}\"")))
            }
            "call_expression" => self.temp_name_call(value, source).map(PathOrigin::TempName),
            _ => None,
        }
    }

    /// The form (a) function a call names, when it produces a file name.
    fn temp_name_call(&self, call: &Node, source: &str) -> Option<&'static str> {
        let (function, spelling) = callee_spelling(call, source)?;
        match self.library_callee(&spelling)? {
            Callee::TempName(n) if !designates_object(&function, source) => Some(n),
            _ => None,
        }
    }
}

/// What reaches a variable's use.
enum Definition<'t> {
    /// An assignment or initializer: the value written.
    Value(Node<'t>),
    /// A form (a) call that wrote a name into it: `tmpnam(buf)`.
    Filled(&'static str),
}

/// The last write before `ident`'s use in its function, in byte order, to
/// the declaration `ident` resolves to (ADR-0006): an assignment, the
/// initializer of that declaration, or a call `fills` names whose first
/// argument is the variable.
fn last_definition<'t>(
    ident: &Node<'t>,
    source: &str,
    fills: impl Fn(&Node<'t>) -> Option<&'static str>,
) -> Option<Definition<'t>> {
    let name = get_node_text(ident, source).trim().to_string();
    let (_, declarator) = resolve_identifier_declarator(ident, &name, source)?;
    let same = |n: &Node<'t>| {
        n.kind() == "identifier"
            && get_node_text(n, source).trim() == name
            && resolve_identifier_declarator(n, &name, source)
                .is_some_and(|(_, d)| d.id() == declarator.id())
    };
    let body = crate::utility::cert_c::ast_utils::ancestors(ident)
        .find(|a| a.kind() == "function_definition")?
        .child_by_field_name("body")?;
    let before = ident.start_byte();
    let mut last: Option<(usize, Definition<'t>)> = None;
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= before {
            continue;
        }
        let found = match node.kind() {
            "init_declarator" if node.end_byte() <= before => node
                .child_by_field_name("value")
                .filter(|_| {
                    node.child_by_field_name("declarator").is_some_and(|d| {
                        d.start_byte() <= declarator.start_byte()
                            && declarator.end_byte() <= d.end_byte()
                    })
                })
                .map(Definition::Value),
            "assignment_expression" if node.end_byte() <= before => {
                let is_plain = node
                    .child_by_field_name("operator")
                    .is_some_and(|op| op.kind() == "=");
                node.child_by_field_name("left")
                    .map(strip)
                    .filter(|l| is_plain && same(l))
                    .and_then(|_| node.child_by_field_name("right"))
                    .map(Definition::Value)
            }
            "call_expression" if node.end_byte() <= before => fills(&node).and_then(|from| {
                let first = node
                    .child_by_field_name("arguments")?
                    .named_child_nodes()
                    .find(|a| a.kind() != "comment")?;
                same(&strip(first)).then_some(Definition::Filled(from))
            }),
            _ => None,
        };
        if let Some(d) = found {
            if last.as_ref().is_none_or(|(at, _)| *at < node.start_byte()) {
                last = Some((node.start_byte(), d));
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    last.map(|(_, d)| d)
}

/// The value a variable holds at its use, when it is a written value.
fn last_value<'t>(ident: &Node<'t>, source: &str) -> Option<Node<'t>> {
    match last_definition(ident, source, |_| None)? {
        Definition::Value(v) => Some(strip(v)),
        Definition::Filled(_) => None,
    }
}

/// Whether a flags expression names `O_CREAT` (or the Windows CRT's
/// `_O_CREAT`).
fn mentions_o_creat(expr: &Node, source: &str) -> bool {
    query::find_first_descendant(*expr, |n| {
        n.kind() == "identifier" && matches!(get_node_text(&n, source), "O_CREAT" | "_O_CREAT")
    })
    .is_some()
}

/// `expr` without the parentheses and casts around it.
fn strip(mut expr: Node) -> Node {
    loop {
        expr = match expr.kind() {
            "parenthesized_expression" => match expr.named_child(0) {
                Some(inner) => inner,
                None => return expr,
            },
            "cast_expression" => match expr.child_by_field_name("value") {
                Some(inner) => inner,
                None => return expr,
            },
            _ => return expr,
        };
    }
}

/// The characters of a string literal between its quotes, escapes as
/// written.
fn literal_content(literal: &Node, source: &str) -> String {
    literal
        .named_child_nodes()
        .filter(|c| matches!(c.kind(), "string_content" | "escape_sequence"))
        .map(|c| get_node_text(&c, source))
        .collect()
}

thread_local! {
    /// One C parser per thread for macro expansions.
    static EXPANSION_PARSER: RefCell<Option<tree_sitter::Parser>> = const { RefCell::new(None) };
}

fn parse_expansion(text: &str) -> Option<tree_sitter::Tree> {
    EXPANSION_PARSER.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            let mut parser = tree_sitter::Parser::new();
            parser.set_language(&crate::parser::c_language()).ok()?;
            *slot = Some(parser);
        }
        slot.as_mut()?.parse(text, None)
    })
}
