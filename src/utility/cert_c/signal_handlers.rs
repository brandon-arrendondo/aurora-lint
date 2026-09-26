// Registered handlers: which functions a translation unit hands to
// `signal`, `sigaction`, `atexit` or `at_quick_exit`, found by what the
// registration call is given rather than by what a function is named.

use crate::analyze::const_eval::collect_macro_aliases;
use crate::analyze::macro_expand::collect_function_macros;
use crate::utility::cert_c::ast_utils::{
    declaration_declarator_for, file_scope_descendants_of_kinds,
    function_names_in_error_declaration, get_identifier_from_declarator, get_node_text,
    resolve_identifier_binding, IdentifierBinding,
};
use crate::utility::cert_c::fn_ptr_bindings::file_scope_function_pointer_bindings;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// How a handler was registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationKind {
    /// `signal(sig, handler)`.
    Signal,
    /// `sigaction(sig, &act, ...)` with `act.sa_handler` or `act.sa_sigaction`
    /// set. `siginfo` is true when the handler is the `sa_sigaction` member or
    /// `sa_flags` is given `SA_SIGINFO`.
    Sigaction {
        /// The handler takes `(int, siginfo_t *, void *)`.
        siginfo: bool,
    },
    /// `atexit(handler)`.
    Atexit,
    /// `at_quick_exit(handler)`.
    AtQuickExit,
}

impl RegistrationKind {
    /// Whether the handler runs on signal delivery (as opposed to at exit).
    pub fn is_signal(&self) -> bool {
        matches!(
            self,
            RegistrationKind::Signal | RegistrationKind::Sigaction { .. }
        )
    }
}

/// One registration of one handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerRegistration {
    /// The function registered.
    pub handler: String,
    /// The signal argument as written (`SIGINT`, `sig`), for a signal
    /// registration. `None` for exit handlers.
    pub signal: Option<String>,
    /// Which API registered it.
    pub kind: RegistrationKind,
    /// For `sigaction`: the signals added to `sa_mask` before the call
    /// (`sigaddset`), or `["*"]` when it is filled (`sigfillset`). Empty for
    /// every other kind, and for a `sigaction` whose mask is left empty.
    pub mask: Vec<String>,
    /// 1-based line and column of the call that names the handler: the
    /// `signal`/`sigaction`/`atexit` call itself, or the wrapper call.
    pub line: usize,
    /// See `line`.
    pub column: usize,
    /// 1-based line and column of the `signal`/`sigaction`/`atexit` call
    /// that performs the registration. For a registration through a wrapper
    /// this is the call inside the wrapper, so it is the same for every
    /// caller of that wrapper.
    pub api_line: usize,
    /// See `api_line`.
    pub api_column: usize,
    /// The project wrapper or macro the registration went through, when it
    /// wasn't a direct call (lua's `setsignal`, a `SIGNAL(s, h)` macro).
    pub via: Option<String>,
    /// Whether this translation unit defines the handler's body. A handler
    /// declared by a prototype and defined elsewhere is still registered.
    pub defined_here: bool,
}

/// Every handler registration in one translation unit.
///
/// **By declaration, not by name** (ADR-0006). A handler argument counts
/// only when it resolves to a function: a file-scope function, or a
/// file-scope function pointer (every function the file binds it to). A
/// name that resolves to a local variable is a saved disposition being put
/// back (`old = signal(SIGPIPE, SIG_IGN); ...; signal(SIGPIPE, old);`), and
/// `SIG_IGN`/`SIG_DFL`/`SIG_ERR`/`NULL`/`0` install no handler. Neither
/// registers anything. A name that resolves to a PARAMETER makes the
/// enclosing function a registration wrapper, and each call of it
/// registers the argument passed in that position.
///
/// **Every registration, not the last one.** A `struct sigaction` whose
/// `sa_handler` is assigned in two arms of an `#if` registers both
/// handlers (ADR-0010: arms are alternatives). The binding is per struct
/// variable, so two `sigaction` calls in one function don't share
/// handlers.
///
/// Macros: an object-like alias (`#define xsignal signal`) is followed, and
/// so is a function-like macro whose body calls `signal`/`sigaction`/
/// `atexit` with its parameters (`#define SIGNAL(s, h) signal(s, h)`).
///
/// Registration through another translation unit's wrapper, or of a handler
/// named only in another file, is out of reach of a per-file pass.
#[derive(Debug, Clone, Default)]
pub struct RegisteredHandlers {
    /// Every registration found, in source order.
    pub registrations: Vec<HandlerRegistration>,
}

impl RegisteredHandlers {
    /// Collect every registration in the translation unit rooted at `root`.
    pub fn collect(root: &Node, source: &str) -> Self {
        Collector::new(root, source).run()
    }

    /// Names of every function registered to run on a signal.
    pub fn signal_handler_names(&self) -> HashSet<String> {
        self.names(|k| k.is_signal())
    }

    /// Names of every function registered with `atexit`/`at_quick_exit`.
    pub fn exit_handler_names(&self) -> HashSet<String> {
        self.names(|k| !k.is_signal())
    }

    /// Every registration of `handler`.
    pub fn of<'s>(&'s self, handler: &'s str) -> impl Iterator<Item = &'s HandlerRegistration> {
        self.registrations
            .iter()
            .filter(move |r| r.handler == handler)
    }

    fn names(&self, want: impl Fn(&RegistrationKind) -> bool) -> HashSet<String> {
        self.registrations
            .iter()
            .filter(|r| want(&r.kind))
            .map(|r| r.handler.clone())
            .collect()
    }
}

/// The registering API a call reaches, with the positions of its signal and
/// handler arguments.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Api {
    Signal,
    Sigaction,
    Atexit,
    AtQuickExit,
}

impl Api {
    fn of(name: &str) -> Option<Api> {
        match name {
            "signal" => Some(Api::Signal),
            "sigaction" => Some(Api::Sigaction),
            "atexit" => Some(Api::Atexit),
            "at_quick_exit" => Some(Api::AtQuickExit),
            _ => None,
        }
    }
}

/// A function or macro that forwards one of its parameters to a registering
/// API: calls to it register the argument in `handler_param`.
#[derive(Clone)]
struct Forwarder {
    api: Api,
    handler_param: usize,
    /// The signal parameter, when the signal is forwarded too; otherwise the
    /// signal is fixed inside the wrapper and given in `fixed_signal`.
    signal_param: Option<usize>,
    fixed_signal: Option<String>,
    siginfo: bool,
    mask: Vec<String>,
    /// Position of the registering API call inside the wrapper.
    api_site: (usize, usize),
}

/// What a handler argument resolves to.
enum HandlerRef {
    Functions(Vec<String>),
    Parameter(usize),
    Nothing,
}

struct Collector<'a, 's> {
    root: Node<'a>,
    source: &'s str,
    functions_defined: HashSet<String>,
    functions_declared: HashSet<String>,
    fn_ptrs: HashMap<String, Vec<String>>,
    aliases: HashMap<String, String>,
    forwarders: HashMap<String, Forwarder>,
    out: Vec<HandlerRegistration>,
}

impl<'a, 's> Collector<'a, 's> {
    fn new(root: &Node<'a>, source: &'s str) -> Self {
        let mut functions_defined = HashSet::new();
        // C has no nested functions, and file_scope_descendants_of_kinds
        // prunes AT function_definition, so it can't return one.
        for def in query::find_descendants_of_kind(*root, "function_definition") {
            if let Some(d) = def.child_by_field_name("declarator") {
                functions_defined.insert(get_identifier_from_declarator(&d, source));
            }
        }
        let mut functions_declared = HashSet::new();
        for decl in file_scope_descendants_of_kinds(*root, &["declaration"]) {
            let mut cursor = decl.walk();
            for d in decl.children_by_field_name("declarator", &mut cursor) {
                if is_function_declarator(&d) {
                    functions_declared.insert(get_identifier_from_declarator(&d, source));
                }
            }
        }
        // A declaration tree-sitter couldn't finish is still a declaration
        // (ADR-0008: diagnose the misread, don't drop the region). hostap's
        // eloop.c recovers `static void eloop_sigsegv_handler(int sig) {` as
        // an ERROR whose children are the function_declarator and `{`, the
        // specifiers stranded outside it -- and, because the recovery still
        // thinks it is inside the struct that opens earlier, the name is a
        // field_identifier. A handler identified only there must still count.
        for err in query::find_descendants_of_kind(*root, "ERROR") {
            functions_declared.extend(function_names_in_error_declaration(&err, source));
            let mut cursor = err.walk();
            for child in err.children(&mut cursor) {
                if child.kind() != "function_declarator" {
                    continue;
                }
                if let Some(name) = child.child_by_field_name("declarator") {
                    if matches!(name.kind(), "identifier" | "field_identifier") {
                        functions_declared.insert(get_node_text(&name, source).to_string());
                    }
                }
            }
        }
        let aliases = collect_macro_aliases(root, source)
            .into_iter()
            .filter(|(_, target)| Api::of(target).is_some())
            .collect();
        Collector {
            root: *root,
            source,
            functions_defined,
            functions_declared,
            fn_ptrs: file_scope_function_pointer_bindings(root, source),
            aliases,
            forwarders: HashMap::new(),
            out: Vec::new(),
        }
    }

    fn run(mut self) -> RegisteredHandlers {
        self.collect_macro_forwarders();
        let calls = query::find_descendants_of_kind(self.root, "call_expression");
        // Wrappers of wrappers: find forwarders until none is new, bounded
        // so a pathological file can't loop.
        for _ in 0..4 {
            let before = self.forwarders.len();
            for call in &calls {
                self.visit(call, true);
            }
            if self.forwarders.len() == before {
                break;
            }
        }
        for call in &calls {
            self.visit(call, false);
        }
        self.out
            .sort_by(|a, b| (a.line, a.column, &a.handler).cmp(&(b.line, b.column, &b.handler)));
        self.out.dedup();
        RegisteredHandlers {
            registrations: self.out,
        }
    }

    /// Resolve one call. In the forwarder pass only wrappers are recorded.
    fn visit(&mut self, call: &Node<'a>, forwarders_only: bool) {
        let Some(function) = call.child_by_field_name("function") else {
            return;
        };
        if function.kind() != "identifier" {
            return;
        }
        let callee = get_node_text(&function, self.source).to_string();
        let args = call_args(call);
        let site = (
            call.start_position().row + 1,
            call.start_position().column + 1,
        );

        if let Some(fwd) = self.forwarders.get(&callee).cloned() {
            if forwarders_only {
                // A wrapper calling a wrapper with its own parameter.
                if let Some(h) = args.get(fwd.handler_param) {
                    if let HandlerRef::Parameter(p) = self.resolve_handler(h) {
                        let sig = fwd.signal_param.and_then(|i| args.get(i));
                        self.record_forwarder(
                            call,
                            Forwarder {
                                handler_param: p,
                                signal_param: sig.and_then(|s| self.parameter_index(s)),
                                fixed_signal: match fwd.signal_param {
                                    Some(i) => args.get(i).map(|s| self.text(s)),
                                    None => fwd.fixed_signal.clone(),
                                },
                                ..fwd
                            },
                        );
                    }
                }
                return;
            }
            if let Some(h) = args.get(fwd.handler_param) {
                if let HandlerRef::Functions(names) = self.resolve_handler(h) {
                    let signal = match fwd.signal_param {
                        Some(i) => args.get(i).map(|s| self.text(s)),
                        None => fwd.fixed_signal.clone(),
                    };
                    for name in names {
                        self.push(
                            name,
                            signal.clone(),
                            kind_of(fwd.api, fwd.siginfo),
                            fwd.mask.clone(),
                            site,
                            fwd.api_site,
                            Some(callee.clone()),
                        );
                    }
                }
            }
            return;
        }

        let api_name = self.aliases.get(&callee).cloned().unwrap_or(callee.clone());
        let Some(api) = Api::of(&api_name) else {
            return;
        };
        let via = (api_name != callee).then(|| callee.clone());
        match api {
            Api::Signal => {
                let (Some(sig), Some(h)) = (args.first(), args.get(1)) else {
                    return;
                };
                self.register(
                    call,
                    api,
                    sig,
                    &[*h],
                    false,
                    Vec::new(),
                    site,
                    via,
                    forwarders_only,
                );
            }
            Api::Atexit | Api::AtQuickExit => {
                let Some(h) = args.first() else {
                    return;
                };
                self.register(
                    call,
                    api,
                    h,
                    &[*h],
                    false,
                    Vec::new(),
                    site,
                    via,
                    forwarders_only,
                );
            }
            Api::Sigaction => {
                let (Some(sig), Some(act)) = (args.first(), args.get(1)) else {
                    return;
                };
                let Some(var) = address_of_variable(act, self.source) else {
                    return;
                };
                let setup = self.sigaction_setup(call, &var);
                self.register(
                    call,
                    api,
                    sig,
                    &setup.handlers,
                    setup.siginfo,
                    setup.mask,
                    site,
                    via,
                    forwarders_only,
                );
            }
        }
    }

    /// Record the registrations (or, in the forwarder pass, the forwarders)
    /// of `handlers` for one registering call.
    #[allow(clippy::too_many_arguments)]
    fn register(
        &mut self,
        call: &Node<'a>,
        api: Api,
        signal: &Node<'a>,
        handlers: &[Node<'a>],
        siginfo: bool,
        mask: Vec<String>,
        site: (usize, usize),
        via: Option<String>,
        forwarders_only: bool,
    ) {
        let is_exit = matches!(api, Api::Atexit | Api::AtQuickExit);
        for h in handlers {
            match self.resolve_handler(h) {
                HandlerRef::Functions(names) if !forwarders_only => {
                    let sig = (!is_exit).then(|| self.text(signal));
                    for name in names {
                        self.push(
                            name,
                            sig.clone(),
                            kind_of(api, siginfo),
                            mask.clone(),
                            site,
                            site,
                            via.clone(),
                        );
                    }
                }
                HandlerRef::Parameter(p) if forwarders_only => {
                    let signal_param = if is_exit {
                        None
                    } else {
                        self.parameter_index(signal)
                    };
                    self.record_forwarder(
                        call,
                        Forwarder {
                            api,
                            handler_param: p,
                            signal_param,
                            fixed_signal: (!is_exit && signal_param.is_none())
                                .then(|| self.text(signal)),
                            siginfo,
                            mask: mask.clone(),
                            api_site: site,
                        },
                    );
                }
                _ => {}
            }
        }
    }

    fn record_forwarder(&mut self, call: &Node<'a>, fwd: Forwarder) {
        let Some(func) = query::nearest_ancestor_of_kind(*call, "function_definition") else {
            return;
        };
        let Some(d) = func.child_by_field_name("declarator") else {
            return;
        };
        let name = get_identifier_from_declarator(&d, self.source);
        self.forwarders.entry(name).or_insert(fwd);
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        handler: String,
        signal: Option<String>,
        kind: RegistrationKind,
        mask: Vec<String>,
        site: (usize, usize),
        api_site: (usize, usize),
        via: Option<String>,
    ) {
        let defined_here = self.functions_defined.contains(&handler);
        let api_site = if api_site == (0, 0) { site } else { api_site };
        self.out.push(HandlerRegistration {
            handler,
            signal,
            kind,
            mask,
            line: site.0,
            column: site.1,
            api_line: api_site.0,
            api_column: api_site.1,
            via,
            defined_here,
        });
    }

    /// What a handler argument names, by declaration.
    fn resolve_handler(&self, arg: &Node<'a>) -> HandlerRef {
        let Some(ident) = strip_to_identifier(arg) else {
            return HandlerRef::Nothing;
        };
        let name = get_node_text(&ident, self.source);
        if matches!(
            name,
            "SIG_IGN" | "SIG_DFL" | "SIG_ERR" | "SIG_HOLD" | "NULL"
        ) {
            return HandlerRef::Nothing;
        }
        match resolve_identifier_binding(&ident, name, self.source) {
            Some(IdentifierBinding::Local(_)) => HandlerRef::Nothing,
            Some(IdentifierBinding::Parameter(_)) => match self.parameter_index(&ident) {
                Some(i) => HandlerRef::Parameter(i),
                None => HandlerRef::Nothing,
            },
            Some(IdentifierBinding::Global(decl)) => {
                if let Some(targets) = self.fn_ptrs.get(name) {
                    return HandlerRef::Functions(targets.clone());
                }
                match declaration_declarator_for(&decl, name, self.source) {
                    Some(d) if is_function_declarator(&d) => {
                        HandlerRef::Functions(vec![name.to_string()])
                    }
                    // A file-scope object that isn't a known function pointer.
                    Some(_) => HandlerRef::Nothing,
                    None => self.function_named(name),
                }
            }
            None => self.function_named(name),
        }
    }

    fn function_named(&self, name: &str) -> HandlerRef {
        if self.functions_defined.contains(name) || self.functions_declared.contains(name) {
            HandlerRef::Functions(vec![name.to_string()])
        } else {
            HandlerRef::Nothing
        }
    }

    /// The position of the enclosing function's parameter that `arg` names.
    fn parameter_index(&self, arg: &Node<'a>) -> Option<usize> {
        let ident = strip_to_identifier(arg)?;
        let name = get_node_text(&ident, self.source);
        if !matches!(
            resolve_identifier_binding(&ident, name, self.source),
            Some(IdentifierBinding::Parameter(_))
        ) {
            return None;
        }
        let func = query::nearest_ancestor_of_kind(ident, "function_definition")?;
        let mut d = func.child_by_field_name("declarator")?;
        while d.kind() != "function_declarator" {
            d = d.child_by_field_name("declarator")?;
        }
        let params = d.child_by_field_name("parameters")?;
        let mut cursor = params.walk();
        let index = params
            .named_children(&mut cursor)
            .filter(|p| p.kind() == "parameter_declaration")
            .position(|p| {
                p.child_by_field_name("declarator")
                    .map(|pd| get_identifier_from_declarator(&pd, self.source) == name)
                    .unwrap_or(false)
            });
        index
    }

    /// The handler values, `SA_SIGINFO` and mask a `struct sigaction`
    /// variable carries into one `sigaction` call: its initializer, and every
    /// assignment in the enclosing function that comes before the call.
    fn sigaction_setup(&self, call: &Node<'a>, var: &str) -> SigactionSetup<'a> {
        let mut setup = SigactionSetup::default();
        let scope =
            query::nearest_ancestor_of_kind(*call, "function_definition").unwrap_or(self.root);
        let end = call.start_byte();

        for init in query::find_descendants_of_kind(scope, "init_declarator") {
            if init.start_byte() >= end {
                continue;
            }
            let (Some(d), Some(value)) = (
                init.child_by_field_name("declarator"),
                init.child_by_field_name("value"),
            ) else {
                continue;
            };
            if get_identifier_from_declarator(&d, self.source) != var {
                continue;
            }
            for pair in query::find_descendants_of_kind(value, "initializer_pair") {
                let field = designator_field(&pair, self.source);
                let Some(v) = pair.child_by_field_name("value") else {
                    continue;
                };
                self.apply_field(&mut setup, field.as_deref(), &v);
            }
        }

        for assign in query::find_descendants_of_kind(scope, "assignment_expression") {
            if assign.start_byte() >= end {
                continue;
            }
            let (Some(left), Some(right)) = (
                assign.child_by_field_name("left"),
                assign.child_by_field_name("right"),
            ) else {
                continue;
            };
            if let Some(field) = member_of(&left, var, self.source) {
                self.apply_field(&mut setup, Some(field), &right);
            }
        }

        for c in query::find_descendants_of_kind(scope, "call_expression") {
            if c.start_byte() >= end {
                continue;
            }
            let Some(f) = c.child_by_field_name("function") else {
                continue;
            };
            let fname = get_node_text(&f, self.source);
            if fname != "sigaddset" && fname != "sigfillset" {
                continue;
            }
            let a = call_args(&c);
            let Some(set) = a.first() else {
                continue;
            };
            let set_text: String = self
                .text(set)
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let mask_of_var = set_text == format!("&{var}.sa_mask")
                || set_text == format!("&{var}->sa_mask")
                || set_text == format!("&({var}).sa_mask");
            if !mask_of_var {
                continue;
            }
            if fname == "sigfillset" {
                setup.mask.push("*".to_string());
            } else if let Some(sig) = a.get(1) {
                setup.mask.push(self.text(sig));
            }
        }
        setup
    }

    fn apply_field(&self, setup: &mut SigactionSetup<'a>, field: Option<&str>, value: &Node<'a>) {
        match field {
            Some("sa_handler") => setup.handlers.push(*value),
            Some("sa_sigaction") => {
                setup.handlers.push(*value);
                setup.siginfo = true;
            }
            Some("sa_flags") if self.text(value).contains("SA_SIGINFO") => setup.siginfo = true,
            _ => {}
        }
    }

    /// `#define SIGNAL(s, h) signal(s, h)`: a function-like macro whose body
    /// is a registering call on its own parameters.
    fn collect_macro_forwarders(&mut self) {
        for (name, m) in collect_function_macros(&self.root, self.source) {
            for (api_name, api) in [
                ("signal", Api::Signal),
                ("sigaction", Api::Sigaction),
                ("atexit", Api::Atexit),
                ("at_quick_exit", Api::AtQuickExit),
            ] {
                let Some(args) = call_args_in_text(&m.body, api_name) else {
                    continue;
                };
                let param = |text: &str| {
                    let t = text
                        .trim()
                        .trim_start_matches('&')
                        .trim_matches(|c| c == '(' || c == ')');
                    m.params.iter().position(|p| p == t.trim())
                };
                let (sig_idx, handler_idx) = match api {
                    Api::Signal => (Some(0), 1),
                    Api::Atexit | Api::AtQuickExit => (None, 0),
                    // The handler of a sigaction macro is inside a struct.
                    Api::Sigaction => continue,
                };
                let Some(handler_param) = args.get(handler_idx).and_then(|a| param(a)) else {
                    continue;
                };
                let signal_param = sig_idx.and_then(|i| args.get(i)).and_then(|a| param(a));
                let fixed_signal = match (sig_idx, signal_param) {
                    (Some(i), None) => args.get(i).map(|s| s.trim().to_string()),
                    _ => None,
                };
                self.forwarders.entry(name.clone()).or_insert(Forwarder {
                    api,
                    handler_param,
                    signal_param,
                    fixed_signal,
                    siginfo: false,
                    mask: Vec::new(),
                    // A macro has no call of its own: the invocation is the site.
                    api_site: (0, 0),
                });
            }
        }
    }

    fn text(&self, n: &Node) -> String {
        get_node_text(n, self.source).trim().to_string()
    }
}

#[derive(Default)]
struct SigactionSetup<'a> {
    handlers: Vec<Node<'a>>,
    siginfo: bool,
    mask: Vec<String>,
}

fn kind_of(api: Api, siginfo: bool) -> RegistrationKind {
    match api {
        Api::Signal => RegistrationKind::Signal,
        Api::Sigaction => RegistrationKind::Sigaction { siginfo },
        Api::Atexit => RegistrationKind::Atexit,
        Api::AtQuickExit => RegistrationKind::AtQuickExit,
    }
}

fn call_args<'a>(call: &Node<'a>) -> Vec<Node<'a>> {
    let Some(args) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = args.walk();
    args.named_children(&mut cursor)
        .filter(|n| n.kind() != "comment")
        .collect()
}

fn is_function_declarator(d: &Node) -> bool {
    let mut cur = *d;
    loop {
        match cur.kind() {
            "function_declarator" => {
                // `void (*fp)(int)` is a pointer, not a function.
                return !cur
                    .child_by_field_name("declarator")
                    .map(|inner| inner.kind() == "parenthesized_declarator")
                    .unwrap_or(false);
            }
            "init_declarator" | "attributed_declarator" => {
                cur = match cur
                    .child_by_field_name("declarator")
                    .or_else(|| cur.named_child(0))
                {
                    Some(n) => n,
                    None => return false,
                };
            }
            _ => return false,
        }
    }
}

/// The identifier an argument names through `&`, casts and parentheses:
/// `handler`, `&handler`, `(sighandler_t)handler`, `(handler)`.
fn strip_to_identifier<'a>(n: &Node<'a>) -> Option<Node<'a>> {
    match n.kind() {
        "identifier" => Some(*n),
        "parenthesized_expression" => n.named_child(0).and_then(|c| strip_to_identifier(&c)),
        "cast_expression" => n
            .child_by_field_name("value")
            .and_then(|c| strip_to_identifier(&c)),
        "pointer_expression" => {
            let op = n.child(0)?;
            if op.kind() == "&" {
                n.child_by_field_name("argument")
                    .and_then(|c| strip_to_identifier(&c))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// `sa` from `&sa`, and `sa` from a pointer argument `psa`.
fn address_of_variable(n: &Node, source: &str) -> Option<String> {
    let ident = match n.kind() {
        "identifier" => *n,
        _ => strip_to_identifier(n)?,
    };
    Some(get_node_text(&ident, source).to_string())
}

/// The member name when `left` is `var.member` or `var->member`.
fn member_of<'s>(left: &Node, var: &str, source: &'s str) -> Option<&'s str> {
    if left.kind() != "field_expression" {
        return None;
    }
    let arg = left.child_by_field_name("argument")?;
    let base = strip_to_identifier(&arg).unwrap_or(arg);
    if get_node_text(&base, source) != var {
        return None;
    }
    let field = left.child_by_field_name("field")?;
    Some(get_node_text(&field, source))
}

/// The field a designated initializer names: `.sa_handler = f`.
fn designator_field(pair: &Node, source: &str) -> Option<String> {
    let designator = pair.child_by_field_name("designator")?;
    let field = if designator.kind() == "field_designator" {
        designator.named_child(0)?
    } else {
        return None;
    };
    Some(get_node_text(&field, source).to_string())
}

/// The top-level, comma-separated arguments of the first `name(` call in a
/// macro body.
fn call_args_in_text(body: &str, name: &str) -> Option<Vec<String>> {
    let bytes = body.as_bytes();
    let mut from = 0;
    while let Some(off) = body[from..].find(name) {
        let start = from + off;
        from = start + name.len();
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let rest = body[from..].trim_start();
        if !before_ok || !rest.starts_with('(') {
            continue;
        }
        let open = body.len() - rest.len();
        let mut depth = 0;
        let mut args = Vec::new();
        let mut cur = String::new();
        for c in body[open..].chars() {
            match c {
                '(' => {
                    depth += 1;
                    if depth == 1 {
                        continue;
                    }
                }
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        args.push(cur.trim().to_string());
                        return Some(args);
                    }
                }
                ',' if depth == 1 => {
                    args.push(cur.trim().to_string());
                    cur.clear();
                    continue;
                }
                _ => {}
            }
            cur.push(c);
        }
        return None;
    }
    None
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(src: &str) -> RegisteredHandlers {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        RegisteredHandlers::collect(&tree.root_node(), src)
    }

    fn handlers(src: &str) -> Vec<(String, Option<String>)> {
        collect(src)
            .registrations
            .into_iter()
            .map(|r| (r.handler, r.signal))
            .collect()
    }

    #[test]
    fn signal_with_address_and_cast() {
        let src = "#include <signal.h>\nvoid h(int s) {}\nvoid g(int s) {}\n\
                   int main(void) { signal(SIGINT, &h); signal(SIGTERM, (void (*)(int))g); return 0; }\n";
        assert_eq!(
            handlers(src),
            vec![
                ("h".into(), Some("SIGINT".into())),
                ("g".into(), Some("SIGTERM".into()))
            ]
        );
    }

    #[test]
    fn ignore_default_and_restore_register_nothing() {
        let src = "#include <signal.h>\nvoid h(int s) {}\n\
                   void f(void) { void (*old)(int) = signal(SIGPIPE, SIG_IGN);\n\
                   signal(SIGINT, SIG_DFL); signal(SIGPIPE, old); }\n";
        assert!(handlers(src).is_empty());
    }

    #[test]
    fn sigaction_assignment_initializer_and_mask() {
        let src = "#include <signal.h>\nvoid h(int s) {}\nvoid info(int s, siginfo_t *i, void *c) {}\n\
                   void f(void) {\n struct sigaction a;\n a.sa_handler = h;\n sigemptyset(&a.sa_mask);\n\
                   sigaddset(&a.sa_mask, SIGUSR1);\n sigaction(SIGUSR1, &a, NULL);\n\
                   struct sigaction b = { .sa_sigaction = info, .sa_flags = SA_SIGINFO };\n\
                   sigaction(SIGSEGV, &b, NULL);\n}\n";
        let r = collect(src).registrations;
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].handler, "h");
        assert_eq!(r[0].mask, vec!["SIGUSR1".to_string()]);
        assert_eq!(r[0].kind, RegistrationKind::Sigaction { siginfo: false });
        assert_eq!(r[1].handler, "info");
        assert_eq!(r[1].signal.as_deref(), Some("SIGSEGV"));
        assert_eq!(r[1].kind, RegistrationKind::Sigaction { siginfo: true });
    }

    #[test]
    fn two_sigaction_structs_keep_their_own_handlers() {
        let src = "#include <signal.h>\nvoid fpe(int s) {}\nvoid term(int s) {}\n\
                   void f(void) { struct sigaction a, b; a.sa_handler = fpe; b.sa_handler = term;\n\
                   sigaction(SIGFPE, &a, 0); sigaction(SIGTERM, &b, 0); }\n";
        assert_eq!(
            handlers(src),
            vec![
                ("fpe".into(), Some("SIGFPE".into())),
                ("term".into(), Some("SIGTERM".into()))
            ]
        );
    }

    #[test]
    fn a_forwarding_wrapper_registers_its_argument() {
        // lua.c's shape.
        let src = "#include <signal.h>\nstatic void laction(int i) {}\n\
                   static void setsignal(int sig, void (*handler)(int)) {\n\
                   struct sigaction sa; sa.sa_handler = handler; sa.sa_flags = 0;\n\
                   sigemptyset(&sa.sa_mask); sigaction(sig, &sa, NULL); }\n\
                   static void docall(void) { setsignal(SIGINT, laction); setsignal(SIGINT, SIG_DFL); }\n";
        let r = collect(src).registrations;
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].handler, "laction");
        assert_eq!(r[0].signal.as_deref(), Some("SIGINT"));
        assert_eq!(r[0].via.as_deref(), Some("setsignal"));
    }

    #[test]
    fn macros_forward_registrations() {
        let src =
            "#include <signal.h>\n#define xsignal signal\n#define SIGNAL(s, h) signal(s, h)\n\
                   void a(int s) {}\nvoid b(int s) {}\n\
                   void f(void) { xsignal(SIGINT, a); SIGNAL(SIGHUP, b); }\n";
        assert_eq!(
            handlers(src),
            vec![
                ("a".into(), Some("SIGINT".into())),
                ("b".into(), Some("SIGHUP".into()))
            ]
        );
    }

    #[test]
    fn atexit_handlers_are_exit_handlers() {
        let src = "#include <stdlib.h>\nvoid bye(void) {}\nvoid q(void) {}\n\
                   int main(void) { atexit(bye); at_quick_exit(q); return 0; }\n";
        let r = collect(src);
        assert_eq!(
            r.exit_handler_names(),
            ["bye", "q"].iter().map(|s| s.to_string()).collect()
        );
        assert!(r.signal_handler_names().is_empty());
    }

    #[test]
    fn a_function_pointer_registers_what_it_is_bound_to() {
        let src = "#include <signal.h>\nvoid h1(int s) {}\nvoid h2(int s) {}\n\
                   static void (*chosen)(int) = h1;\nvoid pick(int x) { if (x) chosen = h2; }\n\
                   void f(void) { signal(SIGINT, chosen); }\n";
        let names = collect(src).signal_handler_names();
        assert!(names.contains("h1") && names.contains("h2"));
    }

    #[test]
    fn a_handler_declared_but_defined_elsewhere_is_still_registered() {
        let src = "#include <signal.h>\nvoid ext(int s);\nvoid f(void) { signal(SIGINT, ext); }\n";
        let r = collect(src).registrations;
        assert_eq!(r.len(), 1);
        assert!(!r[0].defined_here);
    }

    #[test]
    fn a_handler_defined_inside_parse_error_recovery_still_counts() {
        // An unclosed struct: tree-sitter recovers the definition as an
        // ERROR holding a function_declarator named by a field_identifier
        // (the shape hostap's eloop.c produces). The declarator is still the
        // function's declaration (ADR-0008).
        let src = "struct s {\n int a;\nstatic void h(int sig)\n{\n abort();\n}\n\
                   int f(void) { signal(SIGSEGV, h); return 0; }\n";
        assert_eq!(handlers(src), vec![("h".into(), Some("SIGSEGV".into()))]);
    }

    #[test]
    fn an_undeclared_name_is_not_guessed_to_be_a_handler() {
        let src = "#include <signal.h>\nvoid f(void) { signal(SIGINT, mystery); }\n";
        assert!(handlers(src).is_empty());
    }
}
