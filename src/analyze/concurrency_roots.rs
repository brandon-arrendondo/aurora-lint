//! Concurrency-root detection for CON03-C/CON07-C reachability gating.
//!
//! Identifies function names that seed a "reachable from a real concurrent
//! execution context" set: ISR handlers, thread-spawn entry points, and
//! signal handlers. Combined with `ProjectContext::call_graph` (forward
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
//! - No `sigaction()` struct-field registration (`act.sa_handler = fn;`) —
//!   only `signal(SIG, handler)`'s direct 2-argument form. Verified against
//!   the one real-world codebase with labeled CON03-C signal-handler TPs
//!   (mosquitto's `src/signals.c`): it uses `signal()` exclusively.

use crate::analyze::macro_expand::{self, FunctionMacro};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// `(api name, 0-indexed position of the thread-entry-point argument, exact
/// argument count)`. The argument count is checked so an unrelated
/// same-named function (a project's own `signal` wrapper, say) with a
/// different arity doesn't get misread as the libc API.
const THREAD_SPAWN_APIS: &[(&str, usize, usize)] = &[
    // pthread_create(pthread_t *, const pthread_attr_t *, start_routine, arg)
    ("pthread_create", 2, 4),
    // thrd_create(thrd_t *, thrd_start_t func, void *arg)
    ("thrd_create", 1, 3),
    // CreateThread(attrs, stackSize, lpStartAddress, param, flags, threadId)
    ("CreateThread", 2, 6),
];

/// Collect every function name that seeds a concurrent-execution root: an
/// ISR handler (real syntactic evidence, via `lang-parsing-substrate`), a
/// thread-spawn entry point (direct call or forwarded through a
/// function-like macro — see module docs), or a signal handler registered
/// via `signal(SIG, handler)`.
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

    for call in query::find_descendants_of_kind(*root, "call_expression") {
        let Some(function) = call.child_by_field_name("function") else {
            continue;
        };
        if function.kind() != "identifier" {
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
        if let Some(name) = signal_handler_from_call(callee, &arg_texts) {
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

fn thread_entry_from_call(callee: &str, args: &[String]) -> Option<String> {
    let &(_, idx, _) = THREAD_SPAWN_APIS
        .iter()
        .find(|(name, _, arity)| *name == callee && args.len() == *arity)?;
    extract_identifier(args.get(idx)?)
}

fn signal_handler_from_call(callee: &str, args: &[String]) -> Option<String> {
    if callee != "signal" || args.len() != 2 {
        return None;
    }
    let handler = extract_identifier(&args[1])?;
    // SIG_IGN/SIG_DFL are dispositions, not handler functions to treat as roots.
    if handler == "SIG_IGN" || handler == "SIG_DFL" {
        return None;
    }
    Some(handler)
}

/// Scan a fully-expanded macro-invocation text (e.g.
/// `"pthread_create((&t), (NULL), (worker), (arg))"`) for one of the known
/// thread-spawn APIs and extract the start-routine argument, the same way
/// `thread_entry_from_call` would for a literal call site.
fn thread_entry_from_expansion(expansion: &str) -> Option<String> {
    for &(name, idx, arity) in THREAD_SPAWN_APIS {
        if let Some(args) = find_call_args_in_text(expansion, name) {
            if args.len() == arity {
                if let Some(id) = extract_identifier(&args[idx]) {
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

/// Forward-reachability set from `roots` over `call_graph`, treating any
/// edge into `ambiguous_call_targets` as unresolved rather than chasing it
/// (same reasoning as task 562's MSC04-C fix, applied to a reachability
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
        let args = vec![
            "&t".to_string(),
            "NULL".to_string(),
            "worker".to_string(),
            "arg".to_string(),
        ];
        assert_eq!(
            thread_entry_from_call("pthread_create", &args),
            Some("worker".to_string())
        );
    }

    #[test]
    fn thread_entry_wrong_arity_not_matched() {
        let args = vec!["&t".to_string(), "worker".to_string()];
        assert_eq!(thread_entry_from_call("pthread_create", &args), None);
    }

    #[test]
    fn signal_handler_direct() {
        let args = vec!["SIGHUP".to_string(), "handle_signal".to_string()];
        assert_eq!(
            signal_handler_from_call("signal", &args),
            Some("handle_signal".to_string())
        );
    }

    #[test]
    fn signal_handler_ignores_sig_ign() {
        let args = vec!["SIGPIPE".to_string(), "SIG_IGN".to_string()];
        assert_eq!(signal_handler_from_call("signal", &args), None);
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
