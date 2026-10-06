// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! Was a stored function result tested against the value that signals the
//! function's failure?
//!
//! `p = malloc(n);` is handled when some later expression compares `p` with
//! the error value `malloc` returns (`p == NULL`, `!p`, `if (p)`), with no
//! write to `p` in between. This module answers that by the AST:
//!
//! - **Identity, not spelling.** The tested operand has to be the same object
//!   the result was stored in. An identifier is resolved to its declarator
//!   (`resolve_identifier_declarator`), so `!sz` is not a test of `s` and a
//!   shadowing local is not the stored variable (ADR-0006). A field or
//!   subscript target matches the same chain over the same base.
//! - **The error value, not any comparison.** Each function has an
//!   [`ErrorSignal`]: NULL, EOF, a negative value, `(T)-1`, a short count,
//!   `SIG_ERR`, or `errno` and the end pointer for the `strto*` family.
//!   `n == 0` does not detect a negative `snprintf` result.
//! - **A test, not a mention.** The operand has to be compared, negated,
//!   joined by `&&`/`||`, or be a controlling expression. A comment, a string
//!   literal or an unrelated `stderr` nearby credits nothing. A comparison
//!   inside `assert(...)` does not count: `NDEBUG` removes it (ADR-0010).
//! - **Before it is overwritten.** Only occurrences between the store and the
//!   next write to the same object are about the stored result.
//!
//! - **Through a macro.** A result passed whole to a function-like macro is
//!   tested when the macro's expansion tests it: `REQUIRE(p)` for
//!   `#define REQUIRE(x) do { if (!(x)) die(); } while (0)`.
//!
//! "On a path" is approximated by source order inside the enclosing function,
//! like the rest of the AST-level guard queries: a test that follows the
//! store and precedes any rewrite is taken to be reachable from it. The one
//! back edge taken is a loop's: a store in a `while`/`for` body or `for`
//! update is followed by that loop's condition.

use crate::analyze::check_macros::MacroDefinition;
use crate::analyze::macro_expand::{self, FunctionMacro};
use crate::utility::cert_c::ast_utils::{
    ancestors_from_root, declaration_declarator_for, find_containing_function, get_node_text,
    resolve_identifier_declarator, resolve_identifier_declarator_on_path,
};
use crate::utility::cert_c::expr_type::{self, CType, Rank, Sign, TypeEnv};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// How a standard library function signals failure through its return value
/// (C11 7.x, as tabulated by ERR33-C).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorSignal {
    /// A null pointer: `malloc`, `fopen`, `fgets`, `getenv`, ...
    Null,
    /// Nonzero: `fseek`, `remove`, `rename`, `atexit`, ...
    NonZero,
    /// `EOF`: `fgetc`, `fputs`, `ungetc`, ... Only `EOF` (or another
    /// negative constant) or an ordering test sees it: `c == '\n'` does not.
    Eof,
    /// `EOF`, or a count short of the conversions asked for: the scanf
    /// family, where `n == 2` against the expected count is a check.
    Conversions,
    /// A negative value: the printf family (`snprintf` also signals
    /// truncation with a value `>= n`, which any ordering test reads).
    Negative,
    /// A count short of what was asked for (`fread`, `fwrite`), or zero
    /// (`strftime`).
    Count,
    /// `(T)-1`: `ftell`, `time`, `mktime`, `clock`, `mbstowcs`, ...
    MinusOne,
    /// `(size_t)-1` on an encoding error, next to `(size_t)-2` for an
    /// incomplete sequence (and `(size_t)-3` for `mbrtoc16`/`mbrtoc32`): the
    /// restartable conversions. As [`Self::MinusOne`], and any ordering at
    /// a negative constant, `n >= (size_t)-2`, which separates the failing
    /// values from every count.
    Restartable,
    /// `SIG_ERR`: `signal`.
    SigErr,
    /// The value itself does not signal failure: `errno`, or the end pointer
    /// the caller passed in, has to be read (`strtol` and its family).
    ErrnoOrEnd,
    /// No one value is documented as the failure: any test of the result.
    Any,
}

impl ErrorSignal {
    /// Whether the failing value cannot be used at all -- a null pointer, a
    /// negative length, `(T)-1` -- so a use before the test defeats it.
    fn is_unusable_on_failure(self) -> bool {
        matches!(
            self,
            Self::Null | Self::Negative | Self::MinusOne | Self::Restartable
        )
    }
}

/// The error signal of a standard library function, or `None` for one this
/// table does not know.
pub fn error_signal_for(function_name: &str) -> Option<ErrorSignal> {
    Some(match function_name {
        "malloc" | "calloc" | "realloc" | "aligned_alloc" | "fopen" | "freopen" | "tmpfile"
        | "tmpnam" | "fgets" | "fgetws" | "gets" | "setlocale" | "getenv" | "ctime"
        | "localtime" | "gmtime" | "asctime" | "strdup" | "strndup" => ErrorSignal::Null,
        // `fclose` and `fflush` return 0 on success and EOF on failure, so a
        // test against 0 detects their failure as well as one against EOF.
        "fseek" | "fsetpos" | "fgetpos" | "remove" | "rename" | "atexit" | "raise" | "fclose"
        | "fflush" => ErrorSignal::NonZero,
        "fputs" | "fgetc" | "getc" | "getchar" | "fputc" | "putc" | "putchar" | "puts"
        | "ungetc" => ErrorSignal::Eof,
        "scanf" | "fscanf" | "sscanf" | "vscanf" | "vfscanf" | "vsscanf" => {
            ErrorSignal::Conversions
        }
        "printf" | "fprintf" | "sprintf" | "snprintf" | "vprintf" | "vfprintf" | "vsprintf"
        | "vsnprintf" => ErrorSignal::Negative,
        "fread" | "fwrite" | "strftime" | "wcsftime" => ErrorSignal::Count,
        "ftell" | "time" | "mktime" | "clock" | "mbstowcs" | "wcstombs" | "mblen" | "mbtowc"
        | "wctomb" => ErrorSignal::MinusOne,
        "signal" => ErrorSignal::SigErr,
        "strtol" | "strtoul" | "strtoll" | "strtoull" | "strtoimax" | "strtoumax" | "strtof"
        | "strtod" | "strtold" => ErrorSignal::ErrnoOrEnd,
        "system" | "putenv" | "setenv" => ErrorSignal::Any,
        // The rest of ERR33-C's table, by the error return CERT gives.
        "bsearch" | "bsearch_s" | "gets_s" | "gmtime_s" | "localtime_s" | "memchr" | "strchr"
        | "strpbrk" | "strrchr" | "strstr" | "strtok" | "strtok_s" | "wcschr" | "wcspbrk"
        | "wcsrchr" | "wcsstr" | "wcstok" | "wcstok_s" | "wmemchr" => ErrorSignal::Null,
        // Zero on failure, which the null test reads the same way.
        "tss_get" | "wctrans" | "wctype" => ErrorSignal::Null,
        // The table gives `getenv_s` NULL and `wctomb_s` -1, but both return
        // an `errno_t` (C11 K.3.6.2.1, K.3.6.4.1): zero on success.
        "asctime_s" | "at_quick_exit" | "ctime_s" | "fopen_s" | "freopen_s" | "getenv_s"
        | "mbsrtowcs_s" | "mbstowcs_s" | "setvbuf" | "strerror_s" | "tmpfile_s" | "tmpnam_s"
        | "wcsrtombs_s" | "wcstombs_s" | "wctomb_s" => ErrorSignal::NonZero,
        "btowc" | "fgetwc" | "fputwc" | "fputws" | "getwc" | "getwchar" | "putwc" | "ungetwc"
        | "wctob" => ErrorSignal::Eof,
        "fscanf_s" | "fwscanf" | "fwscanf_s" | "scanf_s" | "sscanf_s" | "swscanf" | "swscanf_s"
        | "vfscanf_s" | "vfwscanf" | "vfwscanf_s" | "vscanf_s" | "vsscanf_s" | "vswscanf"
        | "vswscanf_s" | "vwscanf" | "vwscanf_s" | "wscanf" | "wscanf_s" => {
            ErrorSignal::Conversions
        }
        "fprintf_s" | "fwprintf" | "fwprintf_s" | "printf_s" | "snprintf_s" | "sprintf_s"
        | "swprintf" | "swprintf_s" | "thrd_sleep" | "vfprintf_s" | "vfwprintf" | "vfwprintf_s"
        | "vprintf_s" | "vsnprintf_s" | "vsprintf_s" | "vswprintf" | "vswprintf_s"
        | "vwprintf_s" | "wprintf_s" => ErrorSignal::Negative,
        "c16rtomb" | "c32rtomb" | "mbsrtowcs" | "wcrtomb" | "wcsrtombs" => ErrorSignal::MinusOne,
        "mbrlen" | "mbrtoc16" | "mbrtoc32" | "mbrtowc" => ErrorSignal::Restartable,
        "wcstod" | "wcstof" | "wcstoimax" | "wcstol" | "wcstold" | "wcstoll" | "wcstoumax"
        | "wcstoul" | "wcstoull" => ErrorSignal::ErrnoOrEnd,
        // A status other than `thrd_success` (one of several), a length
        // `>= n` for the transforms, or 0 against the `base` success returns
        // (`timespec_get`, canonically tested `!= TIME_UTC`): any test of
        // the result reads it.
        "cnd_broadcast" | "cnd_init" | "cnd_signal" | "cnd_timedwait" | "cnd_wait" | "mtx_init"
        | "mtx_lock" | "mtx_timedlock" | "mtx_trylock" | "mtx_unlock" | "strxfrm"
        | "timespec_get" | "thrd_create" | "thrd_detach" | "thrd_join" | "tss_create"
        | "tss_set" | "wcsxfrm" => ErrorSignal::Any,
        _ => return None,
    })
}

/// Whether the result `store` wrote into `target` is tested against `signal`
/// before `target` is written again.
///
/// `store` is the `assignment_expression` or `init_declarator` that stores the
/// call's result; `target` is its left-hand side (the declarator's name for an
/// `init_declarator`). `call` is the call whose result was stored, which the
/// [`ErrorSignal::ErrnoOrEnd`] case reads its end-pointer argument from.
///
/// The store's own controlling expression counts too:
/// `if ((p = malloc(n)) == NULL)` tests the assignment's value in place.
///
/// `macros` is every macro definition in view: a result passed whole to a
/// function-like macro (`REQUIRE(p)`) is tested when the expansion of every
/// definition of that macro tests it. `types` types the object the result is
/// stored in, which decides whether an ordering test is a signed or an
/// unsigned comparison.
pub fn stored_result_is_tested(
    store: &Node,
    target: &Node,
    call: &Node,
    signal: ErrorSignal,
    source: &str,
    macros: &MacroView,
    types: &TypeEnv,
) -> bool {
    let cx = Cx {
        signal,
        source,
        macros,
        types,
        tree: None,
    };
    tested_from(store, target, call, &cx, MAX_COPY_HOPS)
}

/// [`stored_result_is_tested`] for a caller asking about many stores in one
/// file: identifiers resolve by descending from `tree.root`, and each one's
/// binding is resolved once for the file and kept in `tree.bindings`, rather
/// than climbed to with `Node::parent` (O(depth) a step) again for every
/// store whose candidate occurrences include it. The same answer.
#[allow(clippy::too_many_arguments)]
pub fn stored_result_is_tested_in(
    tree: &FileTree,
    store: &Node,
    target: &Node,
    call: &Node,
    signal: ErrorSignal,
    source: &str,
    macros: &MacroView,
    types: &TypeEnv,
) -> bool {
    let cx = Cx {
        signal,
        source,
        macros,
        types,
        tree: Some(tree),
    };
    tested_from(store, target, call, &cx, MAX_COPY_HOPS)
}

/// One file's tree, for [`stored_result_is_tested_in`].
pub struct FileTree<'a> {
    /// The tree's root: the translation unit.
    pub root: Node<'a>,
    /// Bindings already resolved in this tree; the caller empties it when
    /// the file changes, since node ids are unique only within one tree.
    pub bindings: &'a RefCell<BindingCache>,
}

/// [`FileTree::bindings`]: an identifier's node id to the node id of the
/// declarator binding it (`None` when nothing in the file declares it). Only
/// nodes of the file's own tree are entered, never a macro expansion's.
pub type BindingCache = HashMap<usize, Option<usize>>;

/// What every step of one [`stored_result_is_tested`] query shares.
struct Cx<'s> {
    signal: ErrorSignal,
    source: &'s str,
    macros: &'s MacroView<'s>,
    types: &'s TypeEnv<'s>,
    tree: Option<&'s FileTree<'s>>,
}

/// Every definition of every macro name in view, and the names some
/// configuration leaves undefined: the prescan's `macro_definitions` and
/// `conditional_macro_names` next to the file's own
/// (`check_macros::collect_macro_definitions`,
/// `collect_conditional_macro_names`). A test inside a macro removes a
/// finding, so it counts only when every definition makes it (ADR-0010):
/// an object-like or opaque definition, or a configuration with none at
/// all, is a build in which nothing tests the argument.
pub struct MacroView<'a> {
    /// Every definition of each name, from each table.
    pub defs: [&'a HashMap<String, Vec<MacroDefinition>>; 2],
    /// Names some configuration defines inside a conditional arm only.
    pub conditional: [&'a HashSet<String>; 2],
    /// Verdicts already reached, for the file these tables describe; the
    /// caller empties it when the file changes.
    pub cache: &'a RefCell<MacroTestCache>,
}

/// [`MacroView::cache`]: `(macro, actual arguments with the placeholder,
/// signal, stored unsigned, stored rank, requested count)` to whether every
/// definition tests the placeholder.
pub type MacroTestCache = HashMap<
    (
        String,
        Vec<String>,
        ErrorSignal,
        bool,
        Option<u8>,
        Option<String>,
    ),
    bool,
>;

/// What an ordering test needs to know about the object the result was
/// stored in: whether it holds the value unsigned, its integer rank when it
/// has one, and the types in view, to type a cast constant it is compared
/// with.
#[derive(Clone, Copy)]
struct Stored<'a> {
    unsigned: bool,
    rank: Option<Rank>,
    types: &'a TypeEnv<'a>,
}

/// How many plain copies (`*out = (int)count;`) a result is followed
/// through to the object its test reads.
const MAX_COPY_HOPS: usize = 2;

/// [`stored_result_is_tested`], following a plain copy of the result into
/// another object (`foc = fb;`, `*dataSize = (int)count;`) at most `hops`
/// times: the copy's own test is a test of the result.
fn tested_from(store: &Node, target: &Node, call: &Node, cx: &Cx, hops: usize) -> bool {
    let (signal, source) = (cx.signal, cx.source);
    let stored = stored_object(store, target, source, cx.types, cx.tree);
    let requested = requested_count(call, source);
    let judge = |occ: &Node| {
        occurrence_tests(occ, signal, stored, requested.as_deref(), source)
            || macro_argument_tests(occ, cx, stored, requested.as_deref())
    };
    if signal != ErrorSignal::ErrnoOrEnd && store.kind() == "assignment_expression" && judge(store)
    {
        return true;
    }
    // The store's ancestors, innermost first: from one descent of the root
    // when the tree is known, else by climbing as far as each question asks.
    let held: Option<Vec<Node>> = cx.tree.and_then(|t| {
        let mut path = ancestors_from_root(&t.root, store)?;
        path.reverse();
        path.push(t.root);
        Some(path)
    });
    let store_ancestors = || -> Box<dyn Iterator<Item = Node> + '_> {
        match &held {
            Some(path) => Box::new(path.iter().copied()),
            None => Box::new(std::iter::successors(Some(*store), |n| n.parent()).skip(1)),
        }
    };
    let func = match &held {
        Some(path) => {
            if store.kind() == "function_definition" {
                Some(*store)
            } else {
                path.iter()
                    .copied()
                    .find(|n| n.kind() == "function_definition")
            }
        }
        None => find_containing_function(store),
    };
    let Some(func) = func else {
        return false;
    };
    let Some(body) = func.child_by_field_name("body") else {
        return false;
    };
    let after = store.end_byte();
    let exclusive = |n: &Node| in_exclusive_branches_from(store, n, store_ancestors());
    let same = |a: &Node, b: &Node| same_lvalue_in(cx.tree, a, b, source);

    if signal == ErrorSignal::ErrnoOrEnd {
        return strto_result_is_tested(store, call, &body, source, &exclusive, &same);
    }

    let until = next_write(&body, target, after, &exclusive, &same).unwrap_or(usize::MAX);
    let in_window = |n: &&Node| n.start_byte() >= after && n.start_byte() < until;
    // For a result that is unusable when it signals failure -- a null
    // pointer, a negative length, `(T)-1` -- the test has to come before the
    // value is first used: `p = malloc(n); memset(p, 0, n); if (!p)` tests a
    // pointer already written through. A short count or an EOF is a normal
    // value to consume before the loop test that ends on it.
    let test_first = signal.is_unusable_on_failure();
    let occurrences = candidate_occurrences(&body, target, &same);
    // A store in a loop's body or `for` update is followed by the loop's
    // condition, which sits before it in source order:
    // `for (c = fgetc(f); c != EOF; c = fgetc(f))`, or a priming read
    // `l = fgets(...)` at the bottom of `while (l != NULL) { ... }`. The
    // occurrences are visited in the order control reaches them: the rest of
    // the loop region, the condition, then what follows the region.
    let back_edge = loop_condition_after_from(store, store_ancestors())
        .filter(|&(_, region_end)| until >= region_end);
    let ordered: Vec<&Node> = match back_edge {
        Some((condition, region_end)) => {
            let region = occurrences
                .iter()
                .filter(|o| o.start_byte() >= after && o.start_byte() < region_end);
            let in_condition = occurrences.iter().filter(|o| within(&condition, o));
            let rest = occurrences
                .iter()
                .filter(in_window)
                .filter(|o| o.start_byte() >= region_end);
            region.chain(in_condition).chain(rest).collect()
        }
        None => occurrences.iter().filter(in_window).collect(),
    };
    for occ in ordered {
        if inside_assert(occ, source) || exclusive(occ) {
            continue;
        }
        if judge(occ) {
            return true;
        }
        if hops > 0 {
            if let Some((copy_store, copy_target)) = copy_destination(occ) {
                if tested_from(&copy_store, &copy_target, call, cx, hops - 1) {
                    return true;
                }
            }
        }
        // A comparison that does not look for the error value is still a
        // test, not a use: `t != (time_t)(l_timet)t || t == (time_t)(-1)`
        // reaches its real check a conjunct later. Anything that reads
        // through the value first is a use: `p->len > 0`, `strcmp(p, s)`.
        if test_first && !is_test_operand(occ) && !is_plain_copy(occ) {
            return false;
        }
    }
    false
}

/// Whether `inner` lies inside `outer`'s byte span.
fn within(outer: &Node, inner: &Node) -> bool {
    outer.start_byte() <= inner.start_byte() && inner.end_byte() <= outer.end_byte()
}

/// The condition of the nearest `while`/`for` loop whose body or `for`
/// update holds `store`, and the end of the stretch that runs between the
/// store and that condition: the rest of the body, or nothing for an
/// update. `None` when `store` is in no such position.
fn loop_condition_after_from<'a>(
    store: &Node<'a>,
    ancestors: impl Iterator<Item = Node<'a>>,
) -> Option<(Node<'a>, usize)> {
    let mut current = *store;
    for parent in ancestors {
        match parent.kind() {
            "while_statement" | "for_statement" => {
                let is = |field: &str| {
                    parent
                        .child_by_field_name(field)
                        .is_some_and(|n| n.id() == current.id())
                };
                let region_end = if is("body") {
                    current.end_byte()
                } else if parent.kind() == "for_statement" && is("update") {
                    store.end_byte()
                } else {
                    return None;
                };
                return Some((parent.child_by_field_name("condition")?, region_end));
            }
            "function_definition" => return None,
            _ => current = parent,
        }
    }
    None
}

/// For the `strto*` family: whether `errno` is tested after `store` and
/// before a later `errno = ...` clears it, or the end pointer passed as
/// `&end` is tested before a later call is handed the same pointer. Each
/// event overwrites only its own channel: `errno = 0` leaves the end pointer
/// as this call set it, and a later successful call does not clear errno.
fn strto_result_is_tested(
    store: &Node,
    call: &Node,
    body: &Node,
    source: &str,
    exclusive: &dyn Fn(&Node) -> bool,
    same: &dyn Fn(&Node, &Node) -> bool,
) -> bool {
    let after = store.end_byte();
    let end_ptr = end_pointer_argument(call);
    let errno_reset = query::find_descendants_of_kind(*body, "assignment_expression")
        .into_iter()
        .filter(|a| {
            a.child_by_field_name("left")
                .is_some_and(|l| get_node_text(&strip_parens(l), source) == "errno")
        })
        .map(|a| a.start_byte());
    let end_reused = query::find_descendants_of_kind(*body, "call_expression")
        .into_iter()
        .filter(|c| end_ptr.is_some_and(|e| end_pointer_argument(c).is_some_and(|x| same(&x, &e))))
        .map(|c| c.start_byte());
    let errno_until = errno_reset
        .filter(|&s| s >= after)
        .min()
        .unwrap_or(usize::MAX);
    let end_until = end_reused
        .filter(|&s| s >= after)
        .min()
        .unwrap_or(usize::MAX);
    query::find_descendants_of_kind(*body, "identifier")
        .into_iter()
        .filter(|id| id.start_byte() >= after && !exclusive(id))
        .any(|id| {
            let start = id.start_byte();
            let is_errno = start < errno_until && get_node_text(&id, source) == "errno";
            let is_end = start < end_until && end_ptr.is_some_and(|e| same(&id, &e));
            (is_errno || is_end) && inside_test(&id, source)
        })
}

/// Whether `occ` is passed whole to a function-like macro whose expansion
/// tests it, under every definition of that macro: `REQUIRE(p)` for
/// `#define REQUIRE(x) do { if (!(x)) die(); } while (0)`. The argument is
/// replaced by a placeholder, the invocation expanded once per definition,
/// and the placeholder judged in each expansion as `occ` would be judged in
/// place -- including, for a result unusable on failure, whether the
/// expansion reads through it before testing it. A macro used inside the
/// definition is not expanded in turn, so a test it hides is not seen.
fn macro_argument_tests(occ: &Node, cx: &Cx, stored: Stored, requested: Option<&str>) -> bool {
    const PLACEHOLDER: &str = "__sqc_stored_result__";
    let mut current = *occ;
    while let Some(parent) = current.parent() {
        if !matches!(
            parent.kind(),
            "parenthesized_expression" | "cast_expression"
        ) {
            break;
        }
        current = parent;
    }
    let Some(args) = current.parent().filter(|a| a.kind() == "argument_list") else {
        return false;
    };
    let Some(callee) = args
        .parent()
        .and_then(|c| c.child_by_field_name("function"))
        .filter(|f| f.kind() == "identifier")
    else {
        return false;
    };
    let name = get_node_text(&callee, cx.source);
    if cx.macros.conditional.iter().any(|c| c.contains(name)) {
        return false;
    }
    let alternatives: Vec<&MacroDefinition> = cx
        .macros
        .defs
        .iter()
        .filter_map(|d| d.get(name))
        .flatten()
        .collect();
    if alternatives.is_empty() {
        return false;
    }
    let mut cursor = args.walk();
    let actuals: Vec<String> = args
        .named_children(&mut cursor)
        .filter(|a| a.kind() != "comment")
        .map(|a| {
            if a.id() == current.id() {
                PLACEHOLDER.to_string()
            } else {
                get_node_text(&a, cx.source).to_string()
            }
        })
        .collect();
    if !actuals.iter().any(|a| a == PLACEHOLDER) {
        return false;
    }
    let key = (
        name.to_string(),
        actuals,
        cx.signal,
        stored.unsigned,
        stored.rank.map(|r| r as u8),
        requested.map(str::to_string),
    );
    if let Some(&verdict) = cx.macros.cache.borrow().get(&key) {
        return verdict;
    }
    let verdict = alternatives.iter().all(|alt| match alt {
        MacroDefinition::Function { params, body } => {
            let table = HashMap::from([(
                name.to_string(),
                FunctionMacro {
                    params: params.clone(),
                    body: body.clone(),
                    // This one definition is being judged on its own.
                    alternatives: Vec::new(),
                },
            )]);
            macro_expand::expand_invocation(&table, name, &key.1).is_some_and(|expanded| {
                expansion_tests(&expanded, PLACEHOLDER, cx.signal, stored, requested)
            })
        }
        _ => false,
    });
    cx.macros.cache.borrow_mut().insert(key, verdict);
    verdict
}

/// Whether `placeholder` is tested in the statement `expanded`, judged in
/// order: the first occurrence that is a test credits it, and for a result
/// unusable on failure an earlier use does not.
fn expansion_tests(
    expanded: &str,
    placeholder: &str,
    signal: ErrorSignal,
    stored: Stored,
    requested: Option<&str>,
) -> bool {
    let text = format!("void __sqc_expansion(void) {{ {expanded}; }}");
    let Some(tree) = parse_expansion(&text) else {
        return false;
    };
    let mut ids: Vec<Node> = query::find_descendants_of_kind(tree.root_node(), "identifier")
        .into_iter()
        .filter(|id| get_node_text(id, &text) == placeholder)
        .collect();
    ids.sort_by_key(|id| id.start_byte());
    for id in ids {
        if inside_assert(&id, &text) {
            continue;
        }
        if occurrence_tests(&id, signal, stored, requested, &text) {
            return true;
        }
        if signal.is_unusable_on_failure() && !is_test_operand(&id) {
            return false;
        }
    }
    false
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

/// Whether `occ` is itself an operand of a test, through parentheses and
/// casts only: compared, negated, joined by `&&`/`||`, or a controlling
/// expression. `p->len > 0` and `strcmp(p, s) == 0` read through `p` on the
/// way and are uses of it, not tests.
fn is_test_operand(occ: &Node) -> bool {
    let mut current = *occ;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "parenthesized_expression" | "cast_expression" => current = parent,
            "binary_expression" => {
                return parent.child_by_field_name("operator").is_some_and(|o| {
                    matches!(
                        o.kind(),
                        "==" | "!=" | "<" | ">" | "<=" | ">=" | "&&" | "||"
                    )
                });
            }
            "unary_expression" => {
                return parent
                    .child_by_field_name("operator")
                    .is_some_and(|o| o.kind() == "!");
            }
            "if_statement"
            | "while_statement"
            | "do_statement"
            | "for_statement"
            | "switch_statement"
            | "conditional_expression" => {
                return parent
                    .child_by_field_name("condition")
                    .is_some_and(|c| c.id() == current.id());
            }
            _ => return false,
        }
    }
    false
}

/// The store a plain copy of `occ` makes, and the object it writes: the
/// assignment and its left side, or the initialized declaration and the name
/// it declares. `None` when `occ` is not copied whole.
fn copy_destination<'a>(occ: &Node<'a>) -> Option<(Node<'a>, Node<'a>)> {
    if !is_plain_copy(occ) {
        return None;
    }
    let mut store = occ.parent()?;
    while matches!(store.kind(), "parenthesized_expression" | "cast_expression") {
        store = store.parent()?;
    }
    let target = match store.kind() {
        "assignment_expression" => store.child_by_field_name("left")?,
        _ => {
            let mut d = store.child_by_field_name("declarator")?;
            while d.kind() != "identifier" {
                d = d
                    .child_by_field_name("declarator")
                    .or_else(|| d.named_child(0))?;
            }
            d
        }
    };
    Some((store, target))
}

/// Whether `occ` is copied whole into another object -- the right side of
/// a plain `=` or an initializer (`foc = fb;`, `FILE *g = f;`) -- which
/// moves the value without using it.
fn is_plain_copy(occ: &Node) -> bool {
    let mut current = *occ;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "parenthesized_expression" | "cast_expression" => current = parent,
            "assignment_expression" => {
                return parent
                    .child_by_field_name("operator")
                    .is_some_and(|o| o.kind() == "=")
                    && parent
                        .child_by_field_name("right")
                        .is_some_and(|r| r.id() == current.id());
            }
            "init_declarator" => {
                return parent
                    .child_by_field_name("value")
                    .is_some_and(|v| v.id() == current.id());
            }
            _ => return false,
        }
    }
    false
}

/// For `fread`/`fwrite`, the count the caller asked for (the third
/// argument), whitespace removed -- what a short count is short of.
fn requested_count(call: &Node, source: &str) -> Option<String> {
    let name = call
        .child_by_field_name("function")
        .map(|f| get_node_text(&f, source))?;
    if !matches!(name, "fread" | "fwrite") {
        return None;
    }
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let nmemb = args
        .named_children(&mut cursor)
        .filter(|a| a.kind() != "comment")
        .nth(2)?;
    Some(squeeze(&strip_parens(nmemb), source))
}

/// Every node under `body` that denotes the same object as `target`: an
/// identifier, or a field/subscript expression of the same shape.
fn candidate_occurrences<'a>(
    body: &Node<'a>,
    target: &Node,
    same: &dyn Fn(&Node, &Node) -> bool,
) -> Vec<Node<'a>> {
    query::find_descendants_of_kind(*body, strip_parens(*target).kind())
        .into_iter()
        .filter(|n| same(n, target))
        .collect()
}

/// Start byte of the first write to `target` at or after `after`: a plain or
/// compound assignment to it, or `++`/`--` on it. `None` when nothing
/// rewrites it.
fn next_write(
    body: &Node,
    target: &Node,
    after: usize,
    exclusive: &dyn Fn(&Node) -> bool,
    same: &dyn Fn(&Node, &Node) -> bool,
) -> Option<usize> {
    query::find_descendants_of_kinds(*body, &["assignment_expression", "update_expression"])
        .into_iter()
        .filter(|n| n.start_byte() >= after)
        .filter(|n| !exclusive(n))
        .filter(|n| {
            let written = match n.kind() {
                "assignment_expression" => n.child_by_field_name("left"),
                _ => n.child_by_field_name("argument"),
            };
            written.is_some_and(|w| same(&w, target))
        })
        .map(|n| n.start_byte())
        .min()
}

/// Whether `a` and `b` sit in the two arms of one `if`: one in its
/// consequence, the other in its `else`. Control that ran one has not run
/// the other, so the later one in source order does not follow the earlier.
fn in_exclusive_branches_from<'a>(
    a: &Node<'a>,
    b: &Node,
    a_ancestors: impl Iterator<Item = Node<'a>>,
) -> bool {
    let within = |outer: &Node, inner: &Node| {
        outer.start_byte() <= inner.start_byte() && inner.end_byte() <= outer.end_byte()
    };
    for n in a_ancestors {
        if n.kind() == "if_statement" && within(&n, b) {
            let arm = |field: &str| n.child_by_field_name(field);
            let (Some(then), Some(alt)) = (arm("consequence"), arm("alternative")) else {
                return false;
            };
            return (within(&then, a) && within(&alt, b)) || (within(&alt, a) && within(&then, b));
        }
    }
    false
}

/// Whether `a` and `b` denote the same object: identifiers that resolve to
/// the same declarator (the same spelling when neither resolves, as for a
/// global declared outside the file), or field/subscript chains that match
/// member by member over the same base.
pub fn same_lvalue(a: &Node, b: &Node, source: &str) -> bool {
    same_lvalue_in(None, a, b, source)
}

/// [`same_lvalue`], resolving identifiers through `tree` when it is given:
/// each identifier of the file's tree is resolved once, by descent from its
/// root, and the answer kept.
fn same_lvalue_in(tree: Option<&FileTree>, a: &Node, b: &Node, source: &str) -> bool {
    let (a, b) = (strip_parens(*a), strip_parens(*b));
    match (a.kind(), b.kind()) {
        ("identifier", "identifier") => {
            let (an, bn) = (get_node_text(&a, source), get_node_text(&b, source));
            if an != bn {
                return false;
            }
            match (
                binding_id(tree, &a, an, source),
                binding_id(tree, &b, bn, source),
            ) {
                (Some(da), Some(db)) => da == db,
                (None, None) => true,
                _ => false,
            }
        }
        ("field_expression", "field_expression") => {
            let field = |n: &Node| {
                n.child_by_field_name("field")
                    .map(|f| get_node_text(&f, source).to_string())
            };
            let op = |n: &Node| n.child_by_field_name("operator").map(|o| o.kind());
            field(&a) == field(&b)
                && op(&a) == op(&b)
                && match (
                    a.child_by_field_name("argument"),
                    b.child_by_field_name("argument"),
                ) {
                    (Some(x), Some(y)) => same_lvalue_in(tree, &x, &y, source),
                    _ => false,
                }
        }
        ("subscript_expression", "subscript_expression") => {
            let index = |n: &Node| n.child_by_field_name("index").map(|i| squeeze(&i, source));
            index(&a) == index(&b)
                && match (
                    a.child_by_field_name("argument"),
                    b.child_by_field_name("argument"),
                ) {
                    (Some(x), Some(y)) => same_lvalue_in(tree, &x, &y, source),
                    _ => false,
                }
        }
        ("pointer_expression", "pointer_expression") => {
            match (
                a.child_by_field_name("argument"),
                b.child_by_field_name("argument"),
            ) {
                (Some(x), Some(y)) => {
                    get_node_text(&a, source).starts_with('*')
                        && get_node_text(&b, source).starts_with('*')
                        && same_lvalue_in(tree, &x, &y, source)
                }
                _ => false,
            }
        }
        _ => false,
    }
}

/// The declarator that binds the identifier `ident` (spelled `name`). An
/// identifier that is itself the name a declaration declares binds to that
/// declaration's own declarator; any other occurrence is resolved by scope
/// (`resolve_identifier_declarator`).
fn binding_of<'a>(ident: &Node<'a>, name: &str, source: &str) -> Option<Node<'a>> {
    binding_from(
        ident,
        name,
        source,
        std::iter::successors(Some(*ident), |n| n.parent()).skip(1),
        || resolve_identifier_declarator(ident, name, source),
    )
}

/// The node id of [`binding_of`]'s answer. With `tree`, an identifier of
/// that tree is resolved once, by descent from its root, and kept.
fn binding_id(tree: Option<&FileTree>, ident: &Node, name: &str, source: &str) -> Option<usize> {
    let Some(tree) = tree else {
        return binding_of(ident, name, source).map(|d| d.id());
    };
    if let Some(&known) = tree.bindings.borrow().get(&ident.id()) {
        return known;
    }
    let Some(path) = ancestors_from_root(&tree.root, ident) else {
        // Not of this tree: answer without keeping it.
        return binding_of(ident, name, source).map(|d| d.id());
    };
    let found = binding_on_path(&tree.root, &path, ident, name, source).map(|d| d.id());
    tree.bindings.borrow_mut().insert(ident.id(), found);
    found
}

/// [`binding_of`] for an identifier with `path` = `ancestors_from_root(root,
/// ident)` in hand: its ancestors and its scope come from that one descent.
fn binding_on_path<'a>(
    root: &Node<'a>,
    path: &[Node<'a>],
    ident: &Node<'a>,
    name: &str,
    source: &str,
) -> Option<Node<'a>> {
    let ancestors = path.iter().rev().copied().chain(std::iter::once(*root));
    binding_from(ident, name, source, ancestors, || {
        resolve_identifier_declarator_on_path(root, path, ident, name, source)
    })
}

/// [`binding_of`] over `ident`'s ancestors, innermost first, with the scope
/// resolution it falls back on.
fn binding_from<'a>(
    ident: &Node<'a>,
    name: &str,
    source: &str,
    ancestors: impl Iterator<Item = Node<'a>>,
    resolve: impl FnOnce() -> Option<(Node<'a>, Node<'a>)>,
) -> Option<Node<'a>> {
    let mut current = *ident;
    for parent in ancestors {
        match parent.kind() {
            "pointer_declarator"
            | "array_declarator"
            | "parenthesized_declarator"
            | "init_declarator" => {
                let is_declarator = parent
                    .child_by_field_name("declarator")
                    .is_some_and(|d| d.id() == current.id())
                    || (parent.kind() == "parenthesized_declarator"
                        && parent
                            .named_child(0)
                            .is_some_and(|d| d.id() == current.id()));
                if !is_declarator {
                    break;
                }
                current = parent;
            }
            "declaration" | "parameter_declaration" => {
                // A declaration's declarators are its `declarator` children
                // (several, for `int a, *b = f();`); its type is not one.
                let declares = parent
                    .children_by_field_name("declarator", &mut parent.walk())
                    .any(|d| d.id() == current.id());
                if declares {
                    return declaration_declarator_for(&parent, name, source);
                }
                break;
            }
            _ => break,
        }
    }
    resolve().map(|(_, d)| d)
}

/// Whether the value of `occ` is tested against `signal` where it stands:
/// compared, negated, joined by `&&`/`||`, or used as a controlling
/// expression -- outside any `assert(...)`.
fn occurrence_tests(
    occ: &Node,
    signal: ErrorSignal,
    stored: Stored,
    requested: Option<&str>,
    source: &str,
) -> bool {
    if inside_assert(occ, source) {
        return false;
    }
    let mut current = *occ;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "parenthesized_expression" | "cast_expression" => current = parent,
            "binary_expression" => {
                let op = parent
                    .child_by_field_name("operator")
                    .map(|o| o.kind())
                    .unwrap_or("");
                return match op {
                    "&&" | "||" => truthiness_counts(signal),
                    "==" | "!=" | "<" | ">" | "<=" | ">=" => {
                        let on_left = parent
                            .child_by_field_name("left")
                            .is_some_and(|l| l.id() == current.id());
                        let other = if on_left {
                            parent.child_by_field_name("right")
                        } else {
                            parent.child_by_field_name("left")
                        };
                        // `0 < n` is `n > 0`: judge the result as the left
                        // operand, whichever side it was written on.
                        let op = if on_left { op } else { mirrored(op) };
                        other.is_some_and(|o| {
                            comparison_counts(signal, op, &o, stored, requested, source)
                        })
                    }
                    _ => false,
                };
            }
            "unary_expression" => {
                let is_not = parent
                    .child_by_field_name("operator")
                    .is_some_and(|o| o.kind() == "!");
                return is_not && truthiness_counts(signal);
            }
            "if_statement"
            | "while_statement"
            | "do_statement"
            | "for_statement"
            | "conditional_expression" => {
                let controls = parent
                    .child_by_field_name("condition")
                    .is_some_and(|c| c.id() == current.id());
                return controls && truthiness_counts(signal);
            }
            "switch_statement" => {
                let controls = parent
                    .child_by_field_name("condition")
                    .is_some_and(|c| c.id() == current.id());
                return controls
                    && match signal {
                        ErrorSignal::Null => false,
                        // `switch (c)` sees EOF only through a case for it.
                        ErrorSignal::Eof => switch_has_eof_case(&parent, source),
                        _ => true,
                    };
            }
            _ => return false,
        }
    }
    false
}

/// Whether testing the value for zero/non-zero detects `signal`'s failure.
fn truthiness_counts(signal: ErrorSignal) -> bool {
    matches!(
        signal,
        ErrorSignal::Null | ErrorSignal::NonZero | ErrorSignal::Count | ErrorSignal::Any
    )
}

/// Whether the result is stored as an unsigned value an ordering test then
/// compares unsigned: the stored object's type is an unsigned integer of at
/// least `int`'s rank. A narrower one (`unsigned short n`) promotes to `int`,
/// so `n > -3` is a signed comparison, and always true.
///
/// The object is typed from its declaration, typedefs followed
/// (`typedef size_t mysz;`), or as the expression it is (a member `p->n`,
/// an element `a[0]`). Only an object that cannot be typed falls back on a
/// cast at the store, `(size_t)f(...)`; a typed signed object holds the
/// converted value whatever it was cast to. Anything else reads as signed,
/// the stricter answer.
fn stored_object<'a>(
    store: &Node,
    target: &Node,
    source: &str,
    types: &'a TypeEnv<'a>,
    tree: Option<&FileTree>,
) -> Stored<'a> {
    let ty = stored_type(store, target, source, types, tree).or_else(|| {
        let value = match store.kind() {
            "assignment_expression" => store.child_by_field_name("right"),
            _ => store.child_by_field_name("value"),
        };
        value
            .map(strip_parens)
            .filter(|v| v.kind() == "cast_expression")
            .and_then(|v| v.child_by_field_name("type"))
            .and_then(|t| expr_type::classify_spelling(get_node_text(&t, source), types))
    });
    Stored {
        unsigned: ty.as_ref().is_some_and(is_unsigned_at_least_int),
        rank: match ty {
            Some(CType::Int { rank, .. }) => Some(rank),
            _ => None,
        },
        types,
    }
}

/// The type of the object `store` writes: the declared type for an
/// `init_declarator`, the expression's type for an assignment's left side.
fn stored_type(
    store: &Node,
    target: &Node,
    source: &str,
    types: &TypeEnv,
    tree: Option<&FileTree>,
) -> Option<CType> {
    let target = strip_parens(*target);
    if store.kind() == "assignment_expression" {
        return expr_type::expr_type(&target, source, types);
    }
    if target.kind() != "identifier" {
        return None;
    }
    let name = get_node_text(&target, source);
    // By one descent of the file's tree when it is known, as `binding_id`
    // resolves; else by climbing.
    let declarator = match tree.and_then(|t| Some((t, ancestors_from_root(&t.root, &target)?))) {
        Some((t, path)) => binding_on_path(&t.root, &path, &target, name, source)?,
        None => binding_of(&target, name, source)?,
    };
    let mut decl = declarator;
    while !matches!(decl.kind(), "declaration" | "parameter_declaration") {
        decl = decl.parent()?;
    }
    expr_type::declarator_type(&decl, &declarator, source, types)
}

fn is_unsigned_at_least_int(ty: &CType) -> bool {
    matches!(ty, CType::Int { sign: Sign::Unsigned, rank } if *rank >= Rank::Int)
}

/// The operator that states the same comparison with its operands swapped.
fn mirrored(op: &str) -> &str {
    match op {
        "<" => ">",
        ">" => "<",
        "<=" => ">=",
        ">=" => "<=",
        other => other,
    }
}

/// Whether `value <op> other` detects `signal`'s failure. `unsigned` says the
/// result was stored as an unsigned value, where `-1` has become the type's
/// maximum: an ordering test against `0` or `-1` can no longer see it, and
/// only an equality with `(T)-1` or the expected value does.
fn comparison_counts(
    signal: ErrorSignal,
    op: &str,
    other: &Node,
    stored: Stored,
    requested: Option<&str>,
    source: &str,
) -> bool {
    let o = constant_text(other, source);
    let equality = matches!(op, "==" | "!=");
    if stored.unsigned
        && !equality
        && (o == "0" || is_negative_one(&o))
        && matches!(
            signal,
            ErrorSignal::MinusOne
                | ErrorSignal::Restartable
                | ErrorSignal::Negative
                | ErrorSignal::Eof
                | ErrorSignal::Conversions
                | ErrorSignal::NonZero
        )
    {
        return false;
    }
    match signal {
        ErrorSignal::Null => equality && is_null_constant(&o),
        // Failure is nonzero and, for `fclose`/`fflush`, EOF: an equality
        // with 0 or a negative constant, or an ordering that puts the
        // negative values on the failing side (`r < 0`, `r >= 0`). `r > 0`
        // never sees EOF.
        ErrorSignal::NonZero => {
            if equality {
                o == "0" || is_negative_one(&o)
            } else {
                matches!((op, o.as_str()), ("<", "0") | (">=", "0"))
                    || (is_negative_one(&o) && matches!(op, "<=" | ">"))
            }
        }
        // EOF is seen by an ordering test or an equality with EOF or another
        // negative constant; `c == '\n'` and `c != 0` do not see it.
        ErrorSignal::Eof => !equality || is_negative_constant(&o) || o == "WEOF",
        // `== 0` misses both EOF and a short count (the incorrect checks
        // ERR33-C's CWE-253 half reports); any other comparison reads the
        // value's range or its expected count.
        ErrorSignal::Conversions => !(equality && o == "0"),
        // Only a comparison that can see a negative value: any ordering
        // test, or equality with a negative constant. `n != len` against a
        // length compares the result with another quantity and does not.
        ErrorSignal::Negative => !equality || is_negative_one(&o),
        // An unsigned count is never below zero.
        // A short count is seen against zero, against the count asked for,
        // or against any quantity computed at run time -- not against an
        // unrelated constant (`n > 50`). An unsigned count is never below
        // zero.
        ErrorSignal::Count => {
            if o == "0" {
                !matches!(op, "<" | ">=")
            } else {
                requested == Some(o.as_str()) || !is_integer_literal(&o)
            }
        }
        ErrorSignal::MinusOne => is_negative_one(&o) || (!equality && (o == "0" || o == "-1")),
        // Every failing value sits at the top of `size_t`, above every count:
        // any ordering at a negative constant separates `-1` from them. Only
        // in an unsigned comparison, though: stored signed, the failures are
        // -1, -2 and -3, and `n < -2` or `n <= -1000` sees none of -1. The
        // comparison is unsigned when the result was stored unsigned, or when
        // the constant is cast to an unsigned type, `n >= (size_t)-2`, which
        // converts a signed `n` too.
        // A test at -1 sees it by equality, or by the orderings that put -1
        // on the failing side, `n <= -1` and `n > -1`; `n < -1` and
        // `n >= -1` lump it in with the counts when `n` is signed.
        ErrorSignal::Restartable => {
            (is_negative_one(&o) && (equality || matches!(op, "<=" | ">")))
                || (!equality
                    && (o == "0"
                        || (is_negative_constant(&o)
                            && (stored.unsigned
                                || cast_makes_comparison_unsigned(other, stored, source)))))
        }
        ErrorSignal::SigErr => equality && o == "SIG_ERR",
        ErrorSignal::ErrnoOrEnd => false,
        ErrorSignal::Any => true,
    }
}

/// `other`'s text with whitespace, outer parentheses and casts removed:
/// `(void *)0` -> `0`, `(time_t)(-1)` -> `-1`, `(size_t) -1` -> `-1`.
///
/// A cast to a typedef name the parser cannot know is a type,
/// `(time_t)(-1)`, parses as a call through a parenthesized identifier; that
/// shape is read as the cast it is.
fn constant_text(other: &Node, source: &str) -> String {
    let mut n = strip_parens(*other);
    loop {
        match n.kind() {
            "cast_expression" => match n.child_by_field_name("value") {
                Some(v) => n = strip_parens(v),
                None => break,
            },
            "call_expression" => match typedef_cast_operand(&n, source) {
                Some(v) => n = strip_parens(v),
                None => break,
            },
            // `(time_t) -1` parses as `(time_t)` minus `1`: a parenthesized
            // lone identifier on the left of a binary `-` is the cast.
            "binary_expression"
                if n.child_by_field_name("operator")
                    .is_some_and(|o| o.kind() == "-")
                    && n.child_by_field_name("left").is_some_and(|l| {
                        l.kind() == "parenthesized_expression"
                            && l.named_child(0)
                                .is_some_and(|i| names_no_object(&i, source))
                    }) =>
            {
                return n
                    .child_by_field_name("right")
                    .map(|r| format!("-{}", squeeze(&strip_parens(r), source)))
                    .unwrap_or_default();
            }
            _ => break,
        }
    }
    squeeze(&n, source)
}

/// Whether comparing the stored object with `other` is an unsigned
/// comparison because `other` is a constant cast to an unsigned type:
/// `n >= (size_t)-2`, including the `(T)(x)` and `(T) -x` spellings
/// [`constant_text`] reads as casts.
///
/// The cast type is resolved, typedefs followed, never read off its
/// spelling (ADR-0006). The usual arithmetic conversions make the
/// comparison unsigned only when that type is unsigned, at least `int`'s
/// rank (`(unsigned char)-2` promotes to `int`), and at least the stored
/// object's rank: `long n` against `(unsigned int)-2` is a signed `long`
/// comparison on LP64.
fn cast_makes_comparison_unsigned(other: &Node, stored: Stored, source: &str) -> bool {
    let n = strip_parens(*other);
    let type_node = match n.kind() {
        "cast_expression" => n.child_by_field_name("type"),
        "call_expression" if typedef_cast_operand(&n, source).is_some() => n
            .child_by_field_name("function")
            .and_then(|callee| callee.named_child(0)),
        "binary_expression"
            if n.child_by_field_name("operator")
                .is_some_and(|o| o.kind() == "-") =>
        {
            n.child_by_field_name("left")
                .filter(|l| l.kind() == "parenthesized_expression")
                .and_then(|l| l.named_child(0))
                .filter(|i| names_no_object(i, source))
        }
        _ => None,
    };
    let Some(cast) = type_node
        .and_then(|t| expr_type::classify_spelling(get_node_text(&t, source), stored.types))
    else {
        return false;
    };
    matches!(cast, CType::Int { sign: Sign::Unsigned, rank }
        if rank >= Rank::Int && stored.rank.is_none_or(|stored| rank >= stored))
}

/// The operand of `(T)(x)` misparsed as a call: a parenthesized lone
/// identifier as the callee, and exactly one argument.
fn typedef_cast_operand<'a>(call: &Node<'a>, source: &str) -> Option<Node<'a>> {
    let callee = call.child_by_field_name("function")?;
    if callee.kind() != "parenthesized_expression"
        || !callee
            .named_child(0)
            .is_some_and(|c| names_no_object(&c, source))
    {
        return None;
    }
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let named: Vec<Node> = args
        .named_children(&mut cursor)
        .filter(|a| a.kind() != "comment")
        .collect();
    match named.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

/// Whether `n` is an identifier that no declaration in view binds as an
/// object, so `(n)` in front of an operand can be the cast to a type name
/// the parser does not know: `(time_t) -1` is a cast, `(len) - 1` with a
/// local `len` is a subtraction. A type name declared by `typedef` is not
/// an object declaration and does not resolve.
fn names_no_object(n: &Node, source: &str) -> bool {
    n.kind() == "identifier"
        && resolve_identifier_declarator(n, get_node_text(n, source), source).is_none()
}

/// Whether a `case` of `switch_node` (its own, not a nested switch's) is
/// labelled EOF or a negative constant.
fn switch_has_eof_case(switch_node: &Node, source: &str) -> bool {
    query::find_descendants_of_kind(*switch_node, "case_statement")
        .into_iter()
        .filter(|c| {
            let mut p = c.parent();
            while let Some(n) = p {
                if n.kind() == "switch_statement" {
                    return n.id() == switch_node.id();
                }
                p = n.parent();
            }
            false
        })
        .filter_map(|c| c.child_by_field_name("value"))
        .any(|v| {
            let o = constant_text(&v, source);
            is_negative_constant(&o) || o == "WEOF"
        })
}

fn is_negative_constant(text: &str) -> bool {
    is_negative_one(text) || (text.starts_with('-') && is_integer_literal(text))
}

fn is_integer_literal(text: &str) -> bool {
    let t = text.trim_start_matches('-');
    !t.is_empty() && t.chars().next().is_some_and(|c| c.is_ascii_digit())
}

fn is_null_constant(text: &str) -> bool {
    matches!(text, "NULL" | "0" | "0L" | "nullptr")
}

fn is_negative_one(text: &str) -> bool {
    matches!(text, "-1" | "-1L" | "-1l" | "EOF")
}

/// Whether `node` lies inside an expression that tests something: a
/// controlling expression, a comparison, a `!`, or an `&&`/`||` operand --
/// outside any `assert(...)`. Used for the `errno`/end-pointer reads of the
/// `strto*` family, where what is read may itself be dereferenced
/// (`'\0' != *end`).
fn inside_test(node: &Node, source: &str) -> bool {
    if inside_assert(node, source) {
        return false;
    }
    let mut current = *node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "binary_expression" => {
                let op = parent
                    .child_by_field_name("operator")
                    .map(|o| o.kind())
                    .unwrap_or("");
                if matches!(op, "==" | "!=" | "<" | ">" | "<=" | ">=" | "&&" | "||") {
                    return true;
                }
            }
            "unary_expression"
                if parent
                    .child_by_field_name("operator")
                    .is_some_and(|o| o.kind() == "!") =>
            {
                return true;
            }
            "if_statement"
            | "while_statement"
            | "do_statement"
            | "for_statement"
            | "switch_statement"
            | "conditional_expression" => {
                return parent
                    .child_by_field_name("condition")
                    .is_some_and(|c| c.id() == current.id());
            }
            "expression_statement"
            | "compound_statement"
            | "declaration"
            | "return_statement"
            | "function_definition" => return false,
            _ => {}
        }
        current = parent;
    }
    false
}

/// Whether `node` is an argument of a call to `assert`, which `NDEBUG`
/// removes.
fn inside_assert(node: &Node, source: &str) -> bool {
    let mut current = node.parent();
    while let Some(n) = current {
        match n.kind() {
            "call_expression"
                if n.child_by_field_name("function")
                    .is_some_and(|f| get_node_text(&f, source) == "assert") =>
            {
                return true;
            }
            "expression_statement" | "compound_statement" | "function_definition" => return false,
            _ => {}
        }
        current = n.parent();
    }
    false
}

/// The object whose address a `strto*` call receives as its end pointer
/// (`strtol(s, &end, 10)` -> `end`), or `None` for a null or unrecognized
/// second argument.
fn end_pointer_argument<'a>(call: &Node<'a>) -> Option<Node<'a>> {
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let second = args
        .named_children(&mut cursor)
        .filter(|a| a.kind() != "comment")
        .nth(1)?;
    let second = strip_parens(second);
    if second.kind() != "pointer_expression" {
        return None;
    }
    let is_address = second
        .child_by_field_name("operator")
        .is_some_and(|o| o.kind() == "&");
    if !is_address {
        return None;
    }
    second.child_by_field_name("argument").map(strip_parens)
}

fn strip_parens(mut n: Node) -> Node {
    while n.kind() == "parenthesized_expression" {
        match n.named_child(0) {
            Some(inner) => n = inner,
            None => break,
        }
    }
    n
}

fn squeeze(n: &Node, source: &str) -> String {
    get_node_text(n, source)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        parser.parse(code, None).unwrap()
    }

    /// Whether the first stored call result in `code` (an assignment or an
    /// initialized declaration) is tested against its function's error value.
    /// Asked through both entry points, which must agree.
    fn tested(code: &str) -> bool {
        let climbed = tested_with(code, None);
        let bindings = RefCell::new(BindingCache::new());
        let descended = tested_with(code, Some(&bindings));
        assert_eq!(
            climbed, descended,
            "the two entry points disagree on {code}"
        );
        climbed
    }

    /// [`tested`] through `stored_result_is_tested`, or with `bindings`
    /// through `stored_result_is_tested_in` and a `TypeEnv` given the root.
    fn tested_with(code: &str, bindings: Option<&RefCell<BindingCache>>) -> bool {
        let tree = parse(code);
        let root = tree.root_node();
        fn store_of<'a>(c: &Node<'a>) -> Option<Node<'a>> {
            let mut n = c.parent()?;
            while matches!(n.kind(), "cast_expression" | "parenthesized_expression") {
                n = n.parent()?;
            }
            matches!(n.kind(), "assignment_expression" | "init_declarator").then_some(n)
        }
        let call = query::find_descendants_of_kind(root, "call_expression")
            .into_iter()
            .find(|c| store_of(c).is_some())
            .expect("a stored call");
        let store = store_of(&call).unwrap();
        let target = match store.kind() {
            "assignment_expression" => store.child_by_field_name("left").unwrap(),
            _ => {
                let mut d = store.child_by_field_name("declarator").unwrap();
                while d.kind() != "identifier" {
                    d = d.child_by_field_name("declarator").unwrap();
                }
                d
            }
        };
        let name = get_node_text(&call.child_by_field_name("function").unwrap(), code);
        let signal = error_signal_for(name).unwrap_or(ErrorSignal::Any);
        let defs = crate::analyze::check_macros::collect_macro_definitions(code);
        let conditional = crate::analyze::check_macros::collect_conditional_macro_names(code);
        let empty_defs = HashMap::new();
        let empty_names = HashSet::new();
        let cache = RefCell::new(MacroTestCache::new());
        let macros = MacroView {
            defs: [&empty_defs, &defs],
            conditional: [&empty_names, &conditional],
            cache: &cache,
        };
        let (t, f, sh, al) = (
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );
        let types = TypeEnv::new(&t, &f, &sh, &al, Default::default());
        match bindings {
            None => stored_result_is_tested(&store, &target, &call, signal, code, &macros, &types),
            Some(bindings) => {
                let file = FileTree { root, bindings };
                let types = types.in_tree(root);
                stored_result_is_tested_in(
                    &file, &store, &target, &call, signal, code, &macros, &types,
                )
            }
        }
    }

    /// The binding cache trusts an entry by node id alone, and node ids are
    /// unique only within one live tree: a freed tree's ids can come back in
    /// the next file's. So the caller must empty it per file (ERR33-C does,
    /// in `check`). Entries left from another file -- stood in for here by
    /// keys that name this file's nodes with that file's answers, since
    /// whether an allocator reuses an address is not something a test can
    /// force -- change the verdict.
    #[test]
    fn the_binding_cache_must_be_emptied_between_files() {
        let first = "void f(void) { char *p = malloc(4); if (!p) return; }";
        let bindings = RefCell::new(BindingCache::new());
        assert!(tested_with(first, Some(&bindings)));
        assert!(
            !bindings.borrow().is_empty(),
            "the first file filled the cache"
        );

        // A second file, the cache not emptied: its identifiers' ids now map
        // to stale bindings that disagree with each other.
        let second = "void g(void) { char *q = malloc(4); if (!q) return; }";
        let tree = parse(second);
        let stale: Vec<usize> = bindings.borrow().values().flatten().copied().collect();
        {
            let mut cache = bindings.borrow_mut();
            for (i, ident) in query::find_descendants_of_kind(tree.root_node(), "identifier")
                .into_iter()
                .filter(|n| get_node_text(n, second) == "q")
                .enumerate()
            {
                cache.insert(
                    ident.id(),
                    Some(stale.first().copied().unwrap_or(0) + i + 1),
                );
            }
        }
        let call = query::find_descendants_of_kind(tree.root_node(), "call_expression")[0];
        let store = call.parent().unwrap();
        let target = store.child_by_field_name("declarator").unwrap();
        let target = target.child_by_field_name("declarator").unwrap_or(target);
        let (empty_defs, empty_names) = (HashMap::new(), HashSet::new());
        let macro_cache = RefCell::new(MacroTestCache::new());
        let macros = MacroView {
            defs: [&empty_defs, &empty_defs],
            conditional: [&empty_names, &empty_names],
            cache: &macro_cache,
        };
        let (t, f, sh, al) = (
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );
        let types = TypeEnv::new(&t, &f, &sh, &al, Default::default());
        let file = FileTree {
            root: tree.root_node(),
            bindings: &bindings,
        };
        let signal = error_signal_for("malloc").unwrap_or(ErrorSignal::Any);
        let with_stale = stored_result_is_tested_in(
            &file, &store, &target, &call, signal, second, &macros, &types,
        );
        assert!(
            !with_stale,
            "stale entries make the tested result read as untested"
        );

        bindings.borrow_mut().clear();
        assert!(stored_result_is_tested_in(
            &file, &store, &target, &call, signal, second, &macros, &types
        ));
    }

    #[test]
    fn a_null_test_of_the_stored_pointer_counts() {
        assert!(tested(
            "void f(void) { char *p = malloc(4); if (!p) return; }"
        ));
        assert!(tested(
            "void f(void) { char *p; p = malloc(4); if (p == NULL) return; }"
        ));
        assert!(tested(
            "void f(void) { char *p = malloc(4); if (NULL != p) return; }"
        ));
        assert!(tested(
            "void f(void) { char *p; if ((p = malloc(4)) == NULL) return; }"
        ));
    }

    #[test]
    fn a_similarly_named_variable_is_not_the_result() {
        assert!(!tested(
            "void f(int sz) { char *s = malloc(4); if (!sz) return; }"
        ));
        assert!(!tested(
            "void f(int len, FILE *fp, char *b) { size_t n = fread(b, 1, 4, fp); if (len == 0) return; }"
        ));
    }

    #[test]
    fn a_result_on_the_right_of_a_comparison_is_mirrored() {
        assert!(tested(
            "void f(FILE *fp, char *b) { size_t n = fread(b, 1, 64, fp); if (0 < n) b[n - 1] = 0; }"
        ));
        assert!(!tested(
            "void f(FILE *fp, char *b) { size_t n = fread(b, 1, 64, fp); if (0 > n) return; }"
        ));
    }

    #[test]
    fn a_shadowing_declaration_is_not_the_result() {
        assert!(!tested(
            "void f(void) { char *p = malloc(4); { char *p = 0; if (p == NULL) return; } }"
        ));
    }

    #[test]
    fn a_test_after_the_variable_is_rewritten_is_not_about_the_result() {
        assert!(!tested(
            "void f(void) { FILE *x = fopen(\"a\", \"r\"); x = fopen(\"b\", \"r\"); if (x == NULL) return; }"
        ));
    }

    #[test]
    fn an_assert_is_not_a_test() {
        assert!(!tested(
            "void f(void) { char *p = malloc(4); assert(p != NULL); }"
        ));
    }

    #[test]
    fn the_comparison_has_to_detect_the_error_value() {
        assert!(!tested(
            "void f(char *b) { int n = snprintf(b, 4, \"x\"); if (n == 0) return; }"
        ));
        assert!(tested(
            "void f(char *b) { int n = snprintf(b, 4, \"x\"); if (n < 0) return; }"
        ));
        assert!(tested(
            "void f(char *b) { int n = snprintf(b, 4, \"x\"); if (n >= 4) return; }"
        ));
        assert!(!tested(
            "void f(FILE *fp, char *b) { size_t n = fread(b, 1, 4, fp); if (n < 0) return; }"
        ));
        assert!(tested(
            "void f(FILE *fp, char *b) { size_t n = fread(b, 1, 4, fp); if (n != 4) return; }"
        ));
        assert!(tested(
            "void f(void) { time_t t = time(NULL); if (t == (time_t)(-1)) return; }"
        ));
        assert!(!tested(
            "void f(void) { time_t t = time(NULL); if (t == 0) return; }"
        ));
    }

    #[test]
    fn an_unsigned_copy_of_minus_one_is_not_seen_by_an_ordering_test() {
        assert!(!tested(
            "void f(FILE *fp) { unsigned int n = (unsigned int)ftell(fp); if (n > 0) return; }"
        ));
        assert!(tested(
            "void f(FILE *fp) { long n = ftell(fp); if (n > 0) return; }"
        ));
        assert!(tested(
            "void f(FILE *fp) { long n = ftell(fp); if (n == -1L) return; }"
        ));
    }

    #[test]
    fn a_pointer_used_before_its_null_test_is_not_checked() {
        assert!(!tested(
            "void f(void) { char *p = malloc(4); memset(p, 0, 4); if (p) free(p); }"
        ));
    }

    #[test]
    fn another_comparison_before_the_error_test_is_not_a_use() {
        assert!(tested(
            "void f(struct tm *tm) { time_t t = mktime(tm); if (t != (long)t || t == (time_t)(-1)) return; }"
        ));
    }

    #[test]
    fn copying_the_pointer_before_its_test_is_not_a_use() {
        assert!(tested(
            "void f(FILE **o) { FILE *fb = fopen(\"x\", \"r\"); *o = fb; if (!fb) return; }"
        ));
    }

    #[test]
    fn a_test_of_a_plain_copy_is_a_test_of_the_result() {
        assert!(tested(
            "void f(FILE *fp, char *b, int *out) { size_t count = fread(b, 1, 64, fp); *out = (int)count; if (*out != 64) return; }"
        ));
        assert!(!tested(
            "void f(FILE *fp, char *b, int *out) { size_t count = fread(b, 1, 64, fp); *out = (int)count; }"
        ));
    }

    #[test]
    fn a_typedef_cast_of_minus_one_without_parentheses_is_read() {
        assert!(tested(
            "void f(void) { time_t now; if ((now = time(NULL)) == (time_t) -1) return; }"
        ));
    }

    #[test]
    fn fclose_is_checked_against_zero() {
        assert!(tested(
            "void f(FILE *s) { int ret = fclose(s); if (ret != 0) return; }"
        ));
        assert!(tested(
            "void f(FILE *s) { int ret = fclose(s); if (ret == EOF) return; }"
        ));
    }

    #[test]
    fn a_write_in_the_other_arm_of_an_if_does_not_end_the_window() {
        assert!(tested(
            "void f(int a, struct tm *ts) { time_t t; if (a) t = time(NULL); else t = mktime(ts); if (t == (time_t)(-1)) return; }"
        ));
    }

    #[test]
    fn an_errno_test_in_the_other_arm_does_not_check_this_strtol() {
        assert!(!tested(
            "void f(int a) { long v; if (a) { v = strtol(\"1\", NULL, 0); } else { errno = 0; long w = strtol(\"1\", NULL, 0); if (errno == ERANGE) return; } }"
        ));
    }

    #[test]
    fn a_count_is_compared_with_what_was_asked_for_not_any_constant() {
        assert!(!tested(
            "void f(FILE *fp, char *b) { size_t n = fread(b, 1, 64, fp); if (n > 50) return; }"
        ));
        assert!(tested(
            "void f(FILE *fp, char *b) { size_t n = fread(b, 1, 64, fp); if (n == 64) return; }"
        ));
    }

    #[test]
    fn a_negative_result_is_not_seen_by_equality_with_a_length() {
        assert!(!tested(
            "int w(int); void f(char *b) { int n = snprintf(b, 4, \"x\"); if (w(n) != n) return; }"
        ));
    }

    #[test]
    fn strtol_is_checked_by_errno_or_its_end_pointer_whatever_its_name() {
        assert!(tested(
            "void f(const char *s) { char *end; long v = strtol(s, &end, 10); if (end == s) return; }"
        ));
        assert!(tested(
            "void f(const char *s) { long v = strtol(s, NULL, 10); if (errno == ERANGE) return; }"
        ));
        assert!(!tested(
            "void f(const char *s) { char *end; long v = strtol(s, &end, 10); if (v > 7) return; }"
        ));
    }

    #[test]
    fn a_comment_naming_stderr_is_not_a_test() {
        assert!(!tested(
            "void f(char *b) { int n; /* on failure print to stderr */ n = snprintf(b, 4, \"x\"); puts(b); }"
        ));
    }
}
