// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! Whether a call to a C library function has a side effect, in the sense of
//! C11 5.1.2.3p2: it accesses a volatile object, modifies an object or a
//! file, or calls a function that does. Setting `errno` modifies an object,
//! so `strtol` and the math functions have side effects (CERT PRE31-C-EX1:
//! "even changing errno is a side effect").
//!
//! This is the table behind the `stdlib_call_effects` environment contract
//! (`settings::OPTIONS`). It holds only when a conforming library is declared,
//! so ask it only when that option is true; otherwise a library call is a
//! call to an unknown function.

use super::std_functions::is_iso_c_or_posix_function;

/// What the library contract says about one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryEffect {
    /// Modifies no object, touches no stream, keeps no hidden state and never
    /// sets `errno`.
    Pure,
    /// Its only side effect is on the static result buffer it returns (and,
    /// for `strerror`, `errno` on an invalid code): evaluating it zero times
    /// or twice changes nothing a caller observes beyond that buffer. A policy
    /// may relax these (PRE31-C's `pre31_unknown_call_pure`); the contract as
    /// written still counts them.
    OwnBufferOnly,
    /// Has some side effect: writes through an argument, sets `errno`, does
    /// I/O, allocates, or updates hidden state (`rand`, `strtok`).
    SideEffect,
}

/// Library functions that only compute a value from their arguments and the
/// objects those point to. Kept to functions whose specification lists no
/// error reported through `errno` and no object they modify.
const PURE_LIBRARY_FUNCTIONS: &[&str] = &[
    // <string.h> comparison and search (C11 7.24.4, 7.24.5; not strxfrm or
    // strtok, which write), and strlen (7.24.6.3).
    "memcmp",
    "strcmp",
    "strncmp",
    "strcoll",
    "memchr",
    "strchr",
    "strcspn",
    "strpbrk",
    "strrchr",
    "strspn",
    "strstr",
    "strlen",
    // POSIX <string.h>/<strings.h> read-only counterparts.
    "strnlen",
    "strcasecmp",
    "strncasecmp",
    // <wchar.h> read-only counterparts (C11 7.29.4.4, 7.29.4.5, 7.29.4.6.1).
    "wmemcmp",
    "wcscmp",
    "wcsncmp",
    "wcscoll",
    "wmemchr",
    "wcschr",
    "wcscspn",
    "wcspbrk",
    "wcsrchr",
    "wcsspn",
    "wcsstr",
    "wcslen",
    // <ctype.h> classification and case mapping (C11 7.4).
    "isalnum",
    "isalpha",
    "isblank",
    "iscntrl",
    "isdigit",
    "isgraph",
    "islower",
    "isprint",
    "ispunct",
    "isspace",
    "isupper",
    "isxdigit",
    "tolower",
    "toupper",
    // <wctype.h> (C11 7.30.2).
    "iswalnum",
    "iswalpha",
    "iswblank",
    "iswcntrl",
    "iswdigit",
    "iswgraph",
    "iswlower",
    "iswprint",
    "iswpunct",
    "iswspace",
    "iswupper",
    "iswxdigit",
    "towlower",
    "towupper",
    // POSIX <arpa/inet.h> byte-order conversion.
    "htons",
    "htonl",
    "ntohs",
    "ntohl",
    // <stdlib.h> integer arithmetic (C11 7.22.6).
    "abs",
    "labs",
    "llabs",
    "div",
    "ldiv",
    "lldiv",
    // <math.h> functions with no error condition (C11 7.12.7.2, 7.12.9.1,
    // 7.12.9.2, 7.12.9.6, 7.12.9.8, 7.12.11.1, 7.12.12.2, 7.12.12.3) and the
    // classification macros (7.12.3). Every other math function may report a
    // domain, pole or range error through errno (7.12.1).
    "fabs",
    "fabsf",
    "fabsl",
    "ceil",
    "ceilf",
    "ceill",
    "floor",
    "floorf",
    "floorl",
    "round",
    "roundf",
    "roundl",
    "trunc",
    "truncf",
    "truncl",
    "copysign",
    "copysignf",
    "copysignl",
    "fmax",
    "fmaxf",
    "fmaxl",
    "fmin",
    "fminf",
    "fminl",
    "fpclassify",
    "isfinite",
    "isinf",
    "isnan",
    "isnormal",
    "signbit",
];

/// Functions whose only side effect is the static buffer they return: C11
/// 7.24.6.2 lets a later strerror call overwrite its string (and POSIX lets
/// it set errno for an invalid code); POSIX inet_ntoa returns a static
/// buffer overwritten by the next call.
const OWN_BUFFER_ONLY_FUNCTIONS: &[&str] = &["strerror", "inet_ntoa"];

/// The contract's verdict on a call to `name`, or `None` when `name` is not
/// an ISO C or POSIX function the tool knows (a project function, a Windows
/// API, or a library it has no table for). Classify the resolved name (`resolve_macro_alias`),
/// and only when no scanned file defines `name`: a project's own `strlen`
/// is judged by its body.
pub fn library_call_effect(name: &str) -> Option<LibraryEffect> {
    if PURE_LIBRARY_FUNCTIONS.contains(&name) {
        Some(LibraryEffect::Pure)
    } else if OWN_BUFFER_ONLY_FUNCTIONS.contains(&name) {
        Some(LibraryEffect::OwnBufferOnly)
    } else if is_iso_c_or_posix_function(name) {
        Some(LibraryEffect::SideEffect)
    } else {
        None
    }
}
