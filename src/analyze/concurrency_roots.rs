//! Concurrency-root detection for CON03-C/CON07-C reachability gating.
//!
//! Identifies function names that seed a "reachable from a real concurrent
//! execution context" set: ISR handlers, thread-spawn entry points, and
//! signal handlers. A thread creation is any the thread-API families in
//! force declare (`thread_api::functions_of_kind`), so a project that
//! declares its own spawn function, or selects an RTOS profile, roots its
//! threads' entry functions too. Combined with `ProjectContext::call_graph` (forward
//! reachability from these roots), this is what lets CON03-C/CON07-C stop
//! firing on code that is never reachable from anything concurrent at all
//! (e.g. a single-threaded broker's main loop) — see
//! `docs/design/con03-con07-isr-thread-reachability.md` for the full design
//! and the real-world evidence behind each source below.
//!
//! Deliberately narrow, matching that design doc's non-goals:
//! - No AVR-libc `ISR(vector) { ... }` macro-invocation roots — such a
//!   handler has no resolvable function name (see
//!   `lang_parsing_substrate::InterruptEvidence::MacroInvocation`) and isn't
//!   even a node in `call_graph` (it's excluded the same way
//!   `lang_parsing_substrate::calls`'s `is_macro_function_definition`
//!   excludes it).
//!
//! Signal handlers come from [`RegisteredHandlers`]: `signal()` and
//! `sigaction()` (`sa_handler`/`sa_sigaction`, by assignment or designated
//! initializer), local forwarding wrappers and same-file macros, resolved by
//! declaration. A `signal`-forwarding macro defined in ANOTHER file is still
//! resolved here, through the cross-file macro table.
//!
//! Those registration APIs are not the only roots, though: every function
//! whose caller set is open is one too (`open_caller_set_roots`), because
//! code outside the scanned source calls it from whatever thread it likes.
//! That also covers registrations this module does not resolve -- a
//! `pthread_once` initializer, say, is a static whose address escapes.

use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::macro_expand::{self, FunctionMacro};
use crate::settings::threads::{declared, Role, ThreadOpKind};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::signal_handlers::RegisteredHandlers;
use crate::utility::cert_c::thread_api;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// Thread-creation APIs that no thread-API family declares, as `(api name,
/// 0-indexed position of the thread-entry-point argument, exact argument
/// count)`. The argument count is checked so an unrelated same-named
/// function with a different arity doesn't get misread as the API. Every
/// other thread creation comes from the families in force
/// ([`thread_api::functions_of_kind`]): C11 `thrd_create`, POSIX
/// `pthread_create` when POSIX is read, a selected profile's (FreeRTOS's
/// `xTaskCreate`), and the project's own declared `thread_create` functions.
const UNDECLARED_SPAWN_APIS: &[(&str, usize, usize)] = &[
    // CreateThread(attrs, stackSize, lpStartAddress, param, flags, threadId)
    ("CreateThread", 2, 6),
    // Zephyr RTOS. k_thread_create(thread, stack, stack_size, entry, p1, p2,
    // p3, prio, options, delay) is the runtime spawn; the static
    // `K_THREAD_DEFINE(...)` form is a file-scope macro invocation with no
    // call node and is not resolved here (same limit as the AVR `ISR()`
    // macro noted in the module docs).
    ("k_thread_create", 3, 10),
    // A work item's handler runs on a workqueue thread, never on the
    // submitter's -- the same "entry point of another thread" relation the
    // spawn APIs above express, registered one call earlier.
    // k_work_init(work, handler) / k_work_init_delayable(dwork, handler)
    ("k_work_init", 1, 2),
    ("k_work_init_delayable", 1, 2),
];

/// One way a call names a thread's entry function: the API, the 0-indexed
/// argument the entry is at, and the argument count, when the contract
/// fixes one.
struct Spawn {
    name: String,
    entry: usize,
    arity: Option<usize>,
}

/// Every thread-creation API in force: the declared families' and
/// [`UNDECLARED_SPAWN_APIS`].
fn spawns_in_force() -> Vec<Spawn> {
    let declared = thread_api::functions_of_kind(declared(), ThreadOpKind::ThreadCreate)
        .into_iter()
        .filter_map(|(name, _, op)| {
            Some(Spawn {
                name,
                entry: op.position(Role::Entry)? - 1,
                arity: op.arity,
            })
        });
    declared
        .chain(
            UNDECLARED_SPAWN_APIS
                .iter()
                .map(|&(name, entry, arity)| Spawn {
                    name: name.to_string(),
                    entry,
                    arity: Some(arity),
                }),
        )
        .collect()
}

/// Collect every function name that seeds a concurrent-execution root: an
/// ISR handler (real syntactic evidence, via `lang-parsing-substrate`), a
/// thread-spawn entry point (direct call or forwarded through a
/// function-like macro — see module docs), or a registered signal handler.
///
/// `function_macros` should be the fully cross-file-merged table (this is
/// meant to run after prescan's merge phase, not per-file during the
/// parallel phase — see `prescan.rs`'s call site) so a macro defined in one
/// file (e.g. mosquitto's `pthread_compat.h`) resolves for a call site in
/// another (`thread_mosq.c`).
pub fn collect_concurrency_roots(
    root: &Node,
    source: &str,
    function_macros: &HashMap<String, FunctionMacro>,
    out: &mut HashSet<String>,
) {
    for handler in lang_parsing_substrate::interrupt_handlers(*root, source) {
        if let Some(name) = handler.name {
            out.insert(name);
        }
    }
    out.extend(RegisteredHandlers::collect(root, source).signal_handler_names());

    for call in query::find_descendants_of_kind(*root, "call_expression") {
        let Some(function) = call.child_by_field_name("function") else {
            continue;
        };
        if function.kind() != "identifier" {
            continue;
        }
        // A thread creation of a family in force, resolved by declaration:
        // a local or a pointer of that name creates no thread.
        if let Some(spawn) =
            thread_api::thread_op_of_kind(&call, source, None, ThreadOpKind::ThreadCreate)
        {
            if let Some(name) = spawn
                .operand(Role::Entry)
                .and_then(|entry| extract_identifier(get_node_text(&entry, source)))
            {
                out.insert(name);
            }
            continue;
        }
        let callee = get_node_text(&function, source);
        let Some(args_node) = call.child_by_field_name("arguments") else {
            continue;
        };
        let arg_texts = call_argument_texts(&args_node, source);

        if let Some(name) = thread_entry_from_call(callee, &arg_texts) {
            out.insert(name);
            continue;
        }
        // Not a direct match -- try resolving `callee` as a function-like
        // macro that forwards to one of the known APIs (the
        // COMPAT_pthread_create -> pthread_create case; see module docs).
        if let Some(expansion) =
            macro_expand::expand_invocation(function_macros, callee, &arg_texts)
        {
            if let Some(name) = thread_entry_from_expansion(&expansion) {
                out.insert(name);
            } else if let Some(name) = signal_handler_from_expansion(&expansion) {
                out.insert(name);
            }
        }
    }
}

/// Text of each named argument expression in a `call_expression`'s
/// `arguments` (`argument_list`) node, in order.
fn call_argument_texts(args_node: &Node, source: &str) -> Vec<String> {
    let mut cursor = args_node.walk();
    args_node
        .named_children(&mut cursor)
        .map(|n| get_node_text(&n, source).to_string())
        .collect()
}

/// The entry function a call to one of [`UNDECLARED_SPAWN_APIS`] names.
fn thread_entry_from_call(callee: &str, args: &[String]) -> Option<String> {
    let &(_, idx, _) = UNDECLARED_SPAWN_APIS
        .iter()
        .find(|(name, _, arity)| *name == callee && args.len() == *arity)?;
    extract_identifier(args.get(idx)?)
}

/// Scan a fully-expanded macro-invocation text (e.g.
/// `"pthread_create((&t), (NULL), (worker), (arg))"`) for one of the known
/// thread-spawn APIs and extract the start-routine argument, the same way
/// `thread_entry_from_call` would for a literal call site.
fn thread_entry_from_expansion(expansion: &str) -> Option<String> {
    for spawn in spawns_in_force() {
        if let Some(args) = find_call_args_in_text(expansion, &spawn.name) {
            if spawn.arity.is_none_or(|arity| args.len() == arity) {
                if let Some(id) = args.get(spawn.entry).and_then(|a| extract_identifier(a)) {
                    return Some(id);
                }
            }
        }
    }
    None
}

fn signal_handler_from_expansion(expansion: &str) -> Option<String> {
    let args = find_call_args_in_text(expansion, "signal")?;
    if args.len() != 2 {
        return None;
    }
    let handler = extract_identifier(&args[1])?;
    if handler == "SIG_IGN" || handler == "SIG_DFL" {
        return None;
    }
    Some(handler)
}

/// Find the first whole-word occurrence of `callee(` in `text` and return
/// its top-level, comma-separated argument texts (reusing
/// `macro_expand`'s paren/quote-aware splitter — the same one that
/// produced `text` in the first place, so it's already proven correct on
/// this exact shape of string).
fn find_call_args_in_text(text: &str, callee: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = text.chars().collect();
    let needle: Vec<char> = callee.chars().collect();
    let mut i = 0;
    while i + needle.len() < chars.len() {
        let is_match = chars[i..i + needle.len()] == needle[..] && chars[i + needle.len()] == '(';
        let boundary_ok = i == 0 || !is_ident_char(chars[i - 1]);
        if is_match && boundary_ok {
            let open = i + needle.len();
            if let Some((args, _end)) = macro_expand::parse_call_args(&chars, open) {
                return Some(args);
            }
        }
        i += 1;
    }
    None
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Every function in `summaries` whose caller set is open
/// (`FunctionSummary::caller_set_is_closed` is false), by bare name: an
/// exported function, or a static one whose address escapes. Code outside
/// the scanned source calls such a function, and nothing constrains which
/// thread it calls from -- a library's caller, a plugin, a callback
/// registered with a threaded event loop, a `sigaction` handler or a
/// `pthread_once` initializer. So each is a concurrency root in its own
/// right, which also covers the registration APIs the list above does not
/// name (ADR-0011: in-tree reachability is a caller-set proof like any other).
///
/// Except `main`: the execution environment calls it once, at program
/// startup, before any thread the program creates exists (C11 5.1.2.2).
pub fn open_caller_set_roots<'a>(
    summaries: impl Iterator<Item = (&'a String, &'a FunctionSummary)>,
) -> HashSet<String> {
    summaries
        .filter(|(_, s)| !s.caller_set_is_closed())
        .map(|(key, _)| key.split_once('\0').map_or(key.as_str(), |(_, n)| n))
        .filter(|name| *name != "main")
        .map(str::to_string)
        .collect()
}

/// Forward-reachability set from `roots` over `call_graph`, treating any
/// edge into `ambiguous_call_targets` as unresolved rather than chasing it
/// (same reasoning as an earlier fix's MSC04-C fix, applied to a reachability
/// walk instead of a cycle-detection DFS: a callee resolved only by
/// coincidental name-matching through a struct field or a
/// parameter-shadowed identifier isn't a real call target). Includes the
/// roots themselves. Shared by prescan's cross-file computation
/// (`prescan::compute_concurrency_reachable`) and each rule's same-file
/// fallback (`reachable_within_file`) so the BFS itself isn't duplicated.
pub fn reachable_from_roots(
    roots: &HashSet<String>,
    call_graph: &HashMap<String, HashSet<String>>,
    ambiguous_call_targets: &HashSet<String>,
) -> HashSet<String> {
    let mut reachable: HashSet<String> = HashSet::new();
    let mut queue: Vec<String> = roots.iter().cloned().collect();
    while let Some(current) = queue.pop() {
        if !reachable.insert(current.clone()) {
            continue;
        }
        if let Some(callees) = call_graph.get(&current) {
            for callee in callees {
                if !ambiguous_call_targets.contains(callee) && !reachable.contains(callee) {
                    queue.push(callee.clone());
                }
            }
        }
    }
    reachable
}

/// Same-file fallback for when no `-d` prescan populated
/// `ProjectContext::concurrency_reachable`: computes roots and reachability
/// using only `root`'s own AST — no cross-file call graph, no
/// macro-forwarding resolution beyond what this one file defines, no
/// ambiguous-callee stripping. Reduced recall/precision, same tradeoff
/// every other cross-file-context rule already accepts without `-d` (see
/// the capability catalog's standing caveat on `ProjectContext`).
pub fn reachable_within_file(root: &Node, source: &str) -> HashSet<String> {
    let function_macros = crate::analyze::macro_expand::collect_function_macros(root, source);
    let mut call_graph: HashMap<String, HashSet<String>> = HashMap::new();
    for edge in lang_parsing_substrate::calls::call_edges(*root, source) {
        call_graph
            .entry(edge.caller)
            .or_default()
            .insert(edge.callee);
    }
    let mut roots = HashSet::new();
    collect_concurrency_roots(root, source, &function_macros, &mut roots);
    // This file's own open functions, judged the way the prescan judges
    // them: external linkage, or a static named somewhere as a value.
    let mut value_names = HashSet::new();
    crate::analyze::prescan::collect_value_position_identifiers(root, source, &mut value_names);
    for def in query::find_descendants_of_kind(*root, "function_definition") {
        let Some(name) = crate::analyze::cfg::get_function_name(&def, source) else {
            continue;
        };
        let is_static = crate::utility::cert_c::ast_utils::declaration_has_storage_class(
            &def, "static", source,
        );
        if name != "main" && (!is_static || value_names.contains(name)) {
            roots.insert(name.to_string());
        }
    }
    reachable_from_roots(&roots, &call_graph, &HashSet::new())
}

/// Reduce an argument expression's text to a bare function-name identifier:
/// trims whitespace, strips balanced wrapping parens (macro expansion
/// double-wraps substituted arguments in the macro body's own parens, e.g.
/// `"(mosquitto__thread_main)"`), and strips a leading `&` (a function
/// name decays to a pointer without one, but `&fn` is also legal and seen
/// in the wild). Returns `None` for anything that isn't left as a plain
/// identifier afterward (a struct-field expression, a cast, a more complex
/// expression) — under-detecting a root is safer than fabricating one from
/// an expression that isn't actually a resolvable function name.
fn extract_identifier(raw: &str) -> Option<String> {
    let mut s = raw.trim();
    loop {
        let inner = s.strip_prefix('(').and_then(|s| s.strip_suffix(')'));
        match inner {
            Some(inner) if !inner.is_empty() => s = inner.trim(),
            _ => break,
        }
    }
    let s = s.strip_prefix('&').unwrap_or(s).trim();
    if !s.is_empty()
        && s.chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
        && s.chars().all(is_ident_char)
    {
        Some(s.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_identifier_plain() {
        assert_eq!(extract_identifier("worker"), Some("worker".to_string()));
    }

    #[test]
    fn extract_identifier_address_of() {
        assert_eq!(extract_identifier("&worker"), Some("worker".to_string()));
    }

    #[test]
    fn extract_identifier_macro_wrapped() {
        assert_eq!(
            extract_identifier("(mosquitto__thread_main)"),
            Some("mosquitto__thread_main".to_string())
        );
    }

    #[test]
    fn extract_identifier_rejects_field_expression() {
        assert_eq!(extract_identifier("obj->cb"), None);
    }

    #[test]
    fn extract_identifier_rejects_empty_parens() {
        assert_eq!(extract_identifier("()"), None);
    }

    #[test]
    fn thread_entry_direct_pthread_create() {
        let src = "#include <pthread.h>\nvoid *worker(void *a) { return a; }\n\
                   void f(void) { pthread_t t; pthread_create(&t, NULL, worker, NULL); }\n";
        assert!(roots_of(src).contains("worker"));
    }

    #[test]
    fn thread_entry_direct_thrd_create() {
        let src = "#include <threads.h>\nint worker(void *a) { return 0; }\n\
                   void f(void) { thrd_t t; thrd_create(&t, &worker, NULL); }\n";
        assert!(roots_of(src).contains("worker"));
    }

    #[test]
    fn a_pointer_named_like_a_spawn_creates_no_thread() {
        let src = "void *worker(void *a) { return a; }\n\
                   void f(int (*pthread_create)(void *, void *, void *(*)(void *), void *)) {\n\
                     pthread_create(0, 0, worker, 0);\n\
                   }\n";
        assert!(!roots_of(src).contains("worker"));
    }

    #[test]
    fn thread_entry_zephyr_k_thread_create() {
        let args: Vec<String> = [
            "&tid",
            "stack",
            "STACK_SIZE",
            "sensor_thread",
            "NULL",
            "NULL",
            "NULL",
            "7",
            "0",
            "K_NO_WAIT",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            thread_entry_from_call("k_thread_create", &args),
            Some("sensor_thread".to_string())
        );
    }

    #[test]
    fn thread_entry_zephyr_k_work_init() {
        let args = vec!["&work".to_string(), "work_handler".to_string()];
        assert_eq!(
            thread_entry_from_call("k_work_init", &args),
            Some("work_handler".to_string())
        );
    }

    #[test]
    fn thread_entry_wrong_arity_not_matched() {
        let args = vec!["&t".to_string(), "worker".to_string()];
        assert_eq!(thread_entry_from_call("pthread_create", &args), None);
    }

    fn roots_of(src: &str) -> HashSet<String> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let mut out = HashSet::new();
        collect_concurrency_roots(&tree.root_node(), src, &HashMap::new(), &mut out);
        out
    }

    #[test]
    fn signal_handler_direct() {
        let src = "void handle_signal(int s) {}\nvoid f(void) { signal(SIGHUP, handle_signal); }\n";
        assert!(roots_of(src).contains("handle_signal"));
    }

    #[test]
    fn signal_handler_ignores_sig_ign() {
        let src = "void f(void) { signal(SIGPIPE, SIG_IGN); }\n";
        assert!(roots_of(src).is_empty());
    }

    #[test]
    fn sigaction_handler_is_a_root() {
        let src = "void on_term(int s) {}\n\
                   void f(void) { struct sigaction sa; sa.sa_handler = on_term; sigaction(SIGTERM, &sa, 0); }\n";
        assert!(roots_of(src).contains("on_term"));
    }

    #[test]
    fn thread_entry_via_macro_expansion_mosquitto_shape() {
        // The exact mosquitto COMPAT_pthread_create -> pthread_create shape
        // (see docs/design/con03-con07-isr-thread-reachability.md).
        let expansion =
            "pthread_create((&mosq->thread_id), (NULL), (mosquitto__thread_main), (mosq))";
        assert_eq!(
            thread_entry_from_expansion(expansion),
            Some("mosquitto__thread_main".to_string())
        );
    }

    #[test]
    fn find_call_args_whole_word_boundary() {
        // "my_pthread_create(...)" must not match a search for "pthread_create".
        let text = "my_pthread_create(a, b)";
        assert_eq!(find_call_args_in_text(text, "pthread_create"), None);
    }
}
