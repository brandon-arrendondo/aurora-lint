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
//! "On a path" is approximated by source order inside the enclosing function,
//! like the rest of the AST-level guard queries: a test that follows the
//! store and precedes any rewrite is taken to be reachable from it.

use crate::utility::cert_c::ast_utils::{
    declaration_declarator_for, declaration_type_text, find_containing_function, get_node_text,
    resolve_identifier_declarator,
};
use lang_parsing_substrate::query;
use tree_sitter::Node;

/// How a standard library function signals failure through its return value
/// (C11 7.x, as tabulated by ERR33-C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSignal {
    /// A null pointer: `malloc`, `fopen`, `fgets`, `getenv`, ...
    Null,
    /// Nonzero: `fseek`, `remove`, `rename`, `atexit`, ...
    NonZero,
    /// `EOF` (or a count short of the conversions, for the scanf family).
    Eof,
    /// A negative value: the printf family (`snprintf` also signals
    /// truncation with a value `>= n`, which any ordering test reads).
    Negative,
    /// A count short of what was asked for (`fread`, `fwrite`), or zero
    /// (`strftime`).
    Count,
    /// `(T)-1`: `ftell`, `time`, `mktime`, `clock`, `mbstowcs`, ...
    MinusOne,
    /// `SIG_ERR`: `signal`.
    SigErr,
    /// The value itself does not signal failure: `errno`, or the end pointer
    /// the caller passed in, has to be read (`strtol` and its family).
    ErrnoOrEnd,
    /// No one value is documented as the failure: any test of the result.
    Any,
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
        | "ungetc" | "scanf" | "fscanf" | "sscanf" | "vscanf" | "vfscanf" | "vsscanf" => {
            ErrorSignal::Eof
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
pub fn stored_result_is_tested(
    store: &Node,
    target: &Node,
    call: &Node,
    signal: ErrorSignal,
    source: &str,
) -> bool {
    tested_from(store, target, call, signal, source, MAX_COPY_HOPS)
}

/// How many plain copies (`*out = (int)count;`) a result is followed
/// through to the object its test reads.
const MAX_COPY_HOPS: usize = 2;

/// [`stored_result_is_tested`], following a plain copy of the result into
/// another object (`foc = fb;`, `*dataSize = (int)count;`) at most `hops`
/// times: the copy's own test is a test of the result.
fn tested_from(
    store: &Node,
    target: &Node,
    call: &Node,
    signal: ErrorSignal,
    source: &str,
    hops: usize,
) -> bool {
    if signal != ErrorSignal::ErrnoOrEnd
        && store.kind() == "assignment_expression"
        && occurrence_tests(
            store,
            signal,
            stored_as_unsigned(store, target, source),
            requested_count(call, source).as_deref(),
            source,
        )
    {
        return true;
    }
    let Some(func) = find_containing_function(store) else {
        return false;
    };
    let Some(body) = func.child_by_field_name("body") else {
        return false;
    };
    let after = store.end_byte();
    let until = next_write(&body, store, target, after, source).unwrap_or(usize::MAX);
    let in_window = |n: &Node| n.start_byte() >= after && n.start_byte() < until;

    if signal == ErrorSignal::ErrnoOrEnd {
        let end_ptr = end_pointer_argument(call);
        return query::find_descendants_of_kind(body, "identifier")
            .into_iter()
            .filter(|id| id.start_byte() >= after && !in_exclusive_branches(store, id))
            .any(|id| {
                let is_errno = get_node_text(&id, source) == "errno";
                let is_end = end_ptr.is_some_and(|e| same_lvalue(&id, &e, source));
                (is_errno || is_end) && inside_test(&id, source)
            });
    }

    let unsigned = stored_as_unsigned(store, target, source);
    let requested = requested_count(call, source);
    // For a result that is unusable when it signals failure -- a null
    // pointer, a negative length, `(T)-1` -- the test has to come before the
    // value is first used: `p = malloc(n); memset(p, 0, n); if (!p)` tests a
    // pointer already written through. A short count or an EOF is a normal
    // value to consume before the loop test that ends on it.
    let test_first = matches!(
        signal,
        ErrorSignal::Null | ErrorSignal::Negative | ErrorSignal::MinusOne
    );
    for occ in candidate_occurrences(&body, target, source)
        .into_iter()
        .filter(in_window)
    {
        if inside_assert(&occ, source) || in_exclusive_branches(store, &occ) {
            continue;
        }
        if occurrence_tests(&occ, signal, unsigned, requested.as_deref(), source) {
            return true;
        }
        if hops > 0 {
            if let Some((copy_store, copy_target)) = copy_destination(&occ) {
                if tested_from(&copy_store, &copy_target, call, signal, source, hops - 1) {
                    return true;
                }
            }
        }
        // A comparison that does not look for the error value is still a
        // test, not a use: `t != (time_t)(l_timet)t || t == (time_t)(-1)`
        // reaches its real check a conjunct later.
        if test_first && !inside_test(&occ, source) && !is_plain_copy(&occ) {
            return false;
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
fn candidate_occurrences<'a>(body: &Node<'a>, target: &Node, source: &str) -> Vec<Node<'a>> {
    query::find_descendants_of_kind(*body, strip_parens(*target).kind())
        .into_iter()
        .filter(|n| same_lvalue(n, target, source))
        .collect()
}

/// Start byte of the first write to `target` at or after `after`: a plain or
/// compound assignment to it, or `++`/`--` on it. `None` when nothing
/// rewrites it.
fn next_write(
    body: &Node,
    store: &Node,
    target: &Node,
    after: usize,
    source: &str,
) -> Option<usize> {
    query::find_descendants_of_kinds(*body, &["assignment_expression", "update_expression"])
        .into_iter()
        .filter(|n| n.start_byte() >= after)
        .filter(|n| !in_exclusive_branches(store, n))
        .filter(|n| {
            let written = match n.kind() {
                "assignment_expression" => n.child_by_field_name("left"),
                _ => n.child_by_field_name("argument"),
            };
            written.is_some_and(|w| same_lvalue(&w, target, source))
        })
        .map(|n| n.start_byte())
        .min()
}

/// Whether `a` and `b` sit in the two arms of one `if`: one in its
/// consequence, the other in its `else`. Control that ran one has not run
/// the other, so the later one in source order does not follow the earlier.
fn in_exclusive_branches(a: &Node, b: &Node) -> bool {
    let within = |outer: &Node, inner: &Node| {
        outer.start_byte() <= inner.start_byte() && inner.end_byte() <= outer.end_byte()
    };
    let mut current = a.parent();
    while let Some(n) = current {
        if n.kind() == "if_statement" && within(&n, b) {
            let arm = |field: &str| n.child_by_field_name(field);
            let (Some(then), Some(alt)) = (arm("consequence"), arm("alternative")) else {
                return false;
            };
            return (within(&then, a) && within(&alt, b)) || (within(&alt, a) && within(&then, b));
        }
        current = n.parent();
    }
    false
}

/// Whether `a` and `b` denote the same object: identifiers that resolve to
/// the same declarator (the same spelling when neither resolves, as for a
/// global declared outside the file), or field/subscript chains that match
/// member by member over the same base.
pub fn same_lvalue(a: &Node, b: &Node, source: &str) -> bool {
    let (a, b) = (strip_parens(*a), strip_parens(*b));
    match (a.kind(), b.kind()) {
        ("identifier", "identifier") => {
            let (an, bn) = (get_node_text(&a, source), get_node_text(&b, source));
            if an != bn {
                return false;
            }
            match (binding_of(&a, an, source), binding_of(&b, bn, source)) {
                (Some(da), Some(db)) => da.id() == db.id(),
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
                    (Some(x), Some(y)) => same_lvalue(&x, &y, source),
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
                    (Some(x), Some(y)) => same_lvalue(&x, &y, source),
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
                        && same_lvalue(&x, &y, source)
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
    let mut current = *ident;
    while let Some(parent) = current.parent() {
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
    resolve_identifier_declarator(ident, name, source).map(|(_, d)| d)
}

/// Whether the value of `occ` is tested against `signal` where it stands:
/// compared, negated, joined by `&&`/`||`, or used as a controlling
/// expression -- outside any `assert(...)`.
fn occurrence_tests(
    occ: &Node,
    signal: ErrorSignal,
    unsigned: bool,
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
                            comparison_counts(signal, op, &o, unsigned, requested, source)
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
                return controls && signal != ErrorSignal::Null;
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

/// Whether the stored result lands in an unsigned object: the store casts
/// the call to an unsigned type, or `target` is declared with one. Unsigned
/// by ISO C's own names only -- `unsigned ...`, `size_t`, `uintN_t` and the
/// like -- not by a project typedef, whose signedness is not in view.
fn stored_as_unsigned(store: &Node, target: &Node, source: &str) -> bool {
    let value = match store.kind() {
        "assignment_expression" => store.child_by_field_name("right"),
        _ => store.child_by_field_name("value"),
    };
    if let Some(v) = value.map(strip_parens) {
        if v.kind() == "cast_expression"
            && v.child_by_field_name("type")
                .is_some_and(|t| is_unsigned_type_text(get_node_text(&t, source)))
        {
            return true;
        }
    }
    let target = strip_parens(*target);
    if target.kind() != "identifier" {
        return false;
    }
    let name = get_node_text(&target, source);
    let Some(declarator) = binding_of(&target, name, source) else {
        return false;
    };
    let mut decl = declarator;
    while !matches!(decl.kind(), "declaration" | "parameter_declaration") {
        match decl.parent() {
            Some(p) => decl = p,
            None => return false,
        }
    }
    is_unsigned_type_text(&declaration_type_text(&decl, source))
}

fn is_unsigned_type_text(text: &str) -> bool {
    text.split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|tok| {
            tok == "unsigned"
                || matches!(tok, "size_t" | "uintptr_t" | "uintmax_t")
                || (tok.starts_with("uint") && tok.ends_with("_t"))
        })
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
    unsigned: bool,
    requested: Option<&str>,
    source: &str,
) -> bool {
    let o = constant_text(other, source);
    let equality = matches!(op, "==" | "!=");
    if unsigned
        && !equality
        && (o == "0" || is_negative_one(&o))
        && matches!(
            signal,
            ErrorSignal::MinusOne | ErrorSignal::Negative | ErrorSignal::Eof | ErrorSignal::NonZero
        )
    {
        return false;
    }
    match signal {
        ErrorSignal::Null => equality && is_null_constant(&o),
        ErrorSignal::NonZero => o == "0" || is_negative_one(&o),
        // `== 0` misses both EOF and a negative result (the incorrect checks
        // ERR33-C's CWE-253 half reports); any other comparison reads the
        // value's range or its expected count.
        ErrorSignal::Eof => !(equality && o == "0"),
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
            "call_expression" => match typedef_cast_operand(&n) {
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
                            && l.named_child(0).is_some_and(|i| i.kind() == "identifier")
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

/// The operand of `(T)(x)` misparsed as a call: a parenthesized lone
/// identifier as the callee, and exactly one argument.
fn typedef_cast_operand<'a>(call: &Node<'a>) -> Option<Node<'a>> {
    let callee = call.child_by_field_name("function")?;
    if callee.kind() != "parenthesized_expression"
        || callee.named_child(0).map(|c| c.kind()) != Some("identifier")
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
    fn tested(code: &str) -> bool {
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
        stored_result_is_tested(&store, &target, &call, signal, code)
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
