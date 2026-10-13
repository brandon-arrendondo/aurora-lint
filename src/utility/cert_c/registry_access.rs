// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! Win32 registry calls that take a root key, and whether a call asks for
//! write access to the key it names.
//!
//! Writing under `HKEY_LOCAL_MACHINE` or `HKEY_CLASSES_ROOT` needs
//! administrator rights; reading there does not. So a program that opens an
//! HKLM key for reading asks for nothing it would not have as a standard
//! user, and only a write is the least-privilege question (CWE-272). Each row
//! is the documented contract of one Win32 API: which argument is the root
//! key, and whether the call writes by what it is (it creates, sets or
//! deletes) or by the access mask it passes.
//!
//! A project that defines its own function of a row's name is not calling
//! the Win32 API, so a caller consults the project's function summaries
//! first (`FunctionSummary::registry_write_root_params`) and these rows only
//! for a callee the project does not define.

use super::call_roles::is_win32_api;

/// How a root-key call decides whether it writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryAccess {
    /// The call writes whatever it is passed: it creates a key, or sets or
    /// deletes a key or value.
    Writes,
    /// The call writes when the access mask at this zero-based argument
    /// carries a write right.
    MaskAt(usize),
}

/// The root key is argument 0 of every row.
pub const ROOT_KEY_ARG: usize = 0;

/// Registry calls whose argument 0 is a key handle that may be a predefined
/// root key (`HKEY_LOCAL_MACHINE`), by base name: each matches the
/// `<windows.h>` macro and its `A`/`W` entry points (`call_roles::is_win32_api`).
/// The `RegCreateKey*` calls create the key when it is absent, which needs
/// write access to its parent, so they count as writes whatever mask they
/// pass.
const ROOT_KEY_CALLS: &[(&str, RegistryAccess)] = &[
    ("RegCreateKey", RegistryAccess::Writes),
    ("RegCreateKeyEx", RegistryAccess::Writes),
    ("RegSetValue", RegistryAccess::Writes),
    ("RegSetValueEx", RegistryAccess::Writes),
    ("RegSetKeyValue", RegistryAccess::Writes),
    ("RegDeleteKey", RegistryAccess::Writes),
    ("RegDeleteKeyEx", RegistryAccess::Writes),
    ("RegDeleteValue", RegistryAccess::Writes),
    ("RegDeleteKeyValue", RegistryAccess::Writes),
    ("RegDeleteTree", RegistryAccess::Writes),
    ("RegOpenKeyEx", RegistryAccess::MaskAt(3)),
];

/// Predefined root keys whose subkeys only an administrator may write.
const PRIVILEGED_ROOT_KEYS: &[&str] = &["HKEY_LOCAL_MACHINE", "HKEY_CLASSES_ROOT"];

/// Access-mask names (`winnt.h`/`winreg.h`) that carry a write right to a
/// key: setting a value, creating a subkey or link, deleting, or changing the
/// key's security. `MAXIMUM_ALLOWED` is not here: it asks for whatever the
/// caller's token allows and fails nothing for a standard user.
const WRITE_RIGHTS: &[&str] = &[
    "KEY_WRITE",
    "KEY_ALL_ACCESS",
    "KEY_SET_VALUE",
    "KEY_CREATE_SUB_KEY",
    "KEY_CREATE_LINK",
    "DELETE",
    "WRITE_DAC",
    "WRITE_OWNER",
    "GENERIC_WRITE",
    "GENERIC_ALL",
];

/// Access-mask names that carry no write right, read without looking them
/// up: so a read mask settles without a search of the headers.
const READ_RIGHTS: &[&str] = &[
    "KEY_READ",
    "KEY_QUERY_VALUE",
    "KEY_ENUMERATE_SUB_KEYS",
    "KEY_NOTIFY",
    "KEY_EXECUTE",
    "KEY_WOW64_32KEY",
    "KEY_WOW64_64KEY",
    "READ_CONTROL",
    "SYNCHRONIZE",
    "STANDARD_RIGHTS_READ",
    "GENERIC_READ",
    "GENERIC_EXECUTE",
    "MAXIMUM_ALLOWED",
];

/// The predefined root keys, privileged or not: a name that settles the
/// root without a search of the headers.
const ROOT_KEYS: &[&str] = &[
    "HKEY_LOCAL_MACHINE",
    "HKEY_CLASSES_ROOT",
    "HKEY_CURRENT_USER",
    "HKEY_USERS",
    "HKEY_CURRENT_CONFIG",
    "HKEY_PERFORMANCE_DATA",
    "HKEY_DYN_DATA",
];

/// The bits of [`WRITE_RIGHTS`], for a mask spelled as a number.
const WRITE_RIGHT_BITS: u64 = 0x0002 // KEY_SET_VALUE
    | 0x0004 // KEY_CREATE_SUB_KEY
    | 0x0020 // KEY_CREATE_LINK
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

/// The row for a Win32 registry call that takes a root key, if `function`
/// names one.
pub fn root_key_call(function: &str) -> Option<RegistryAccess> {
    ROOT_KEY_CALLS
        .iter()
        .find(|(base, _)| is_win32_api(function, base))
        .map(|(_, access)| *access)
}

/// Whether `key` names a predefined root key whose subkeys need
/// administrator rights to write.
pub fn is_privileged_root_key(key: &str) -> bool {
    PRIVILEGED_ROOT_KEYS.contains(&key)
}

/// What a macro name may stand for where it is used: every replacement list
/// a definition in force there gives it, empty for a name no macro defines.
pub type Expand<'a> = &'a dyn Fn(&str) -> Vec<String>;

/// The first term `text` may stand for that `found` accepts. Each
/// `|`-separated term, with its casts and parentheses removed
/// ([`bare_term`]), is tried as written and then, unless it is a name or
/// number that settles itself (a mask right, a root key), through every
/// replacement list `expand` gives it, read the same way. A name whose
/// definitions disagree is one build per definition, so any of them that
/// reaches an accepted term counts (ADR-0010 D1). Each name is expanded once
/// per question, so a macro that names itself, directly or through others,
/// ends the walk there, and the walk is linear in the definitions it reaches
/// however many alternatives each has.
pub fn reaches(text: &str, expand: Expand, found: &dyn Fn(&str) -> bool) -> Option<String> {
    let mut queue: std::collections::VecDeque<String> = [text.to_string()].into();
    let mut expanded: std::collections::HashSet<String> = std::collections::HashSet::new();
    while let Some(text) = queue.pop_front() {
        for term in text.split('|') {
            let term = bare_term(term);
            if term.is_empty() {
                continue;
            }
            if found(term) {
                return Some(term.to_string());
            }
            if settles_itself(term) || !expanded.insert(term.to_string()) {
                continue;
            }
            queue.extend(expand(term));
        }
    }
    None
}

/// Whether the access mask spelled `mask` carries a write right: a term that
/// is a write right's name ([`WRITE_RIGHTS`]) or a number with one of their
/// bits, as written or through a macro ([`reaches`]: `(REGSAM)(KEY_WRITE)`,
/// `#define APP_ACCESS KEY_WRITE`, `#define M (KEY_READ | KEY_SET_VALUE)`). A
/// term that is none of these, such as a variable, is not taken for a write.
/// `MAXIMUM_ALLOWED` is not a write: it asks for whatever the caller's token
/// allows.
pub fn mask_requests_write(mask: &str, expand: Expand) -> bool {
    reaches(mask, expand, &|term| {
        WRITE_RIGHTS.contains(&term) || parse_mask(term).is_some_and(|v| v & WRITE_RIGHT_BITS != 0)
    })
    .is_some()
}

/// The privileged root key `arg` names, through casts, parentheses and
/// macros ([`reaches`]): `(HKEY)(HKEY_LOCAL_MACHINE)`, or `ROOT` after
/// `#define ROOT (HKEY_LOCAL_MACHINE)`.
pub fn privileged_root_key(arg: &str, expand: Expand) -> Option<String> {
    reaches(arg, expand, &is_privileged_root_key)
}

/// Whether a call to the root-key row `access`, with argument texts `args`,
/// asks for write access. A mask argument that is missing is not a write.
pub fn call_writes(access: RegistryAccess, args: &[&str], expand: Expand) -> bool {
    match access {
        RegistryAccess::Writes => true,
        RegistryAccess::MaskAt(i) => args
            .get(i)
            .is_some_and(|mask| mask_requests_write(mask, expand)),
    }
}

/// A term whose meaning needs no macro lookup: a mask right, a root key or
/// a number. So a Win32 spelling settles without a search of the headers.
fn settles_itself(term: &str) -> bool {
    WRITE_RIGHTS.contains(&term)
        || READ_RIGHTS.contains(&term)
        || ROOT_KEYS.contains(&term)
        || parse_mask(term).is_some()
}

/// One term without its casts and parentheses: `(REGSAM)KEY_WRITE`,
/// `((REGSAM)KEY_WRITE)`, `(REGSAM)(KEY_WRITE` (the left half of a
/// parenthesized `|`) and `KEY_WRITE))` are each `KEY_WRITE`. A leading
/// parenthesized group, matched to its own closing parenthesis, is the whole
/// term when only closing parentheses follow it, and a cast, dropped, when
/// it holds only a type name (identifiers and spaces) and more text follows.
/// An opening parenthesis left unmatched by a split is dropped.
pub fn bare_term(term: &str) -> &str {
    let mut term = term.trim();
    while let Some(inner_start) = term.strip_prefix('(') {
        let mut depth = 0usize;
        let close = inner_start.char_indices().find_map(|(i, c)| match c {
            '(' => {
                depth += 1;
                None
            }
            ')' if depth == 0 => Some(i),
            ')' => {
                depth -= 1;
                None
            }
            _ => None,
        });
        let Some(close) = close else {
            term = inner_start.trim();
            continue;
        };
        let inner = inner_start[..close].trim();
        let rest = inner_start[close + 1..].trim();
        let is_type_name = !inner.is_empty()
            && inner
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ' ')
            && !inner.starts_with(|c: char| c.is_ascii_digit());
        if rest.chars().all(|c| c == ')') {
            term = inner;
        } else if is_type_name {
            term = rest;
        } else {
            break;
        }
    }
    term.trim_end_matches(')').trim()
}

/// An integer literal, decimal or hex, with any `u`/`l` suffix.
fn parse_mask(term: &str) -> Option<u64> {
    let digits = term.trim_end_matches(['u', 'U', 'l', 'L']);
    match digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => digits.parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none(_: &str) -> Vec<String> {
        Vec::new()
    }

    /// An expansion table: each name's replacement lists.
    fn table<'a>(rows: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Vec<String> + 'a {
        move |t: &str| {
            rows.iter()
                .filter(|(name, _)| *name == t)
                .map(|(_, body)| body.to_string())
                .collect()
        }
    }

    #[test]
    fn casts_and_parentheses_around_a_mask_term_are_read_through() {
        for mask in [
            "KEY_WRITE",
            "(KEY_WRITE)",
            "(REGSAM)KEY_WRITE",
            "(REGSAM)(KEY_WRITE)",
            "((REGSAM)KEY_WRITE)",
            "(((REGSAM)(KEY_WRITE)))",
            "(REGSAM)(KEY_READ | KEY_SET_VALUE)",
            "((REGSAM)KEY_READ | (REGSAM)KEY_WRITE)",
            "KEY_READ | (DWORD)0x2",
        ] {
            assert!(mask_requests_write(mask, &none), "{mask}");
        }
        for mask in [
            "KEY_READ",
            "(REGSAM)KEY_READ",
            "((REGSAM)KEY_READ)",
            "(REGSAM)(KEY_READ | 0x1)",
            "MAXIMUM_ALLOWED",
            "access",
        ] {
            assert!(!mask_requests_write(mask, &none), "{mask}");
        }
    }

    #[test]
    fn a_macro_body_is_read_as_a_mask_with_its_parentheses_and_ors() {
        let rows = [
            ("M2", "(KEY_SET_VALUE)"),
            ("M3", "(KEY_READ | KEY_SET_VALUE)"),
            ("M4", "KEY_READ | KEY_SET_VALUE"),
            ("M5", "((REGSAM)KEY_WRITE)"),
            ("R", "(KEY_READ)"),
        ];
        let expand = table(&rows);
        for mask in ["M2", "M3", "M4", "M5", "(REGSAM)M3", "((REGSAM)M2)"] {
            assert!(mask_requests_write(mask, &expand), "{mask}");
        }
        assert!(!mask_requests_write("R", &expand));
    }

    #[test]
    fn a_root_key_is_read_through_casts_parentheses_and_macros() {
        let rows = [
            ("ROOT", "(HKEY_LOCAL_MACHINE)"),
            ("REGKEY_HKLM", "HKEY_LOCAL_MACHINE"),
            ("MYR", "((HKEY)HKEY_LOCAL_MACHINE)"),
            ("CHAIN", "MYR"),
            ("USER", "(HKEY_CURRENT_USER)"),
        ];
        let expand = table(&rows);
        for arg in [
            "HKEY_LOCAL_MACHINE",
            "(HKEY)(HKEY_LOCAL_MACHINE)",
            "((HKEY)HKEY_LOCAL_MACHINE)",
            "(HKEY_LOCAL_MACHINE)",
            "ROOT",
            "(HKEY)REGKEY_HKLM",
            "MYR",
            "CHAIN",
        ] {
            assert_eq!(
                privileged_root_key(arg, &expand).as_deref(),
                Some("HKEY_LOCAL_MACHINE"),
                "{arg}"
            );
        }
        assert_eq!(privileged_root_key("USER", &expand), None);
    }

    #[test]
    fn an_alias_is_read_as_the_mask_it_names() {
        let rows = [("APP_ACCESS", "KEY_WRITE")];
        let expand = table(&rows);
        assert!(mask_requests_write("APP_ACCESS", &expand));
        assert!(mask_requests_write("(REGSAM)APP_ACCESS", &expand));
    }

    #[test]
    fn any_definition_of_a_name_that_writes_makes_it_a_write() {
        let rows = [("A", "KEY_READ"), ("A", "B"), ("B", "(KEY_SET_VALUE)")];
        assert!(mask_requests_write("A", &table(&rows)));
        let rows = [("A", "KEY_READ"), ("A", "B"), ("B", "KEY_QUERY_VALUE")];
        assert!(!mask_requests_write("A", &table(&rows)));
    }

    #[test]
    fn a_cycle_of_macros_ends_the_walk_and_does_not_accuse() {
        let rows = [("A", "B"), ("A", "(B)"), ("B", "A"), ("B", "(A)")];
        assert!(!mask_requests_write("A", &table(&rows)));
        assert_eq!(privileged_root_key("A", &table(&rows)), None);
        let rows = [("A", "B | (B|A)"), ("B", "A"), ("B", "KEY_WRITE")];
        assert!(mask_requests_write("A", &table(&rows)));
    }

    #[test]
    fn a_wide_fan_of_alternatives_is_walked_once_per_name() {
        // 40 names, each with 6 definitions naming the next and a reader:
        // walking every combination would never finish.
        let mut rows: Vec<(String, String)> = Vec::new();
        for i in 0..40 {
            for j in 0..6 {
                rows.push((format!("X{i}"), format!("(X{} | Y{j})", i + 1)));
            }
        }
        rows.push(("X40".into(), "KEY_SET_VALUE".into()));
        let calls = std::cell::Cell::new(0usize);
        let expand = |t: &str| {
            calls.set(calls.get() + 1);
            rows.iter()
                .filter(|(name, _)| name == t)
                .map(|(_, body)| body.clone())
                .collect()
        };
        assert!(mask_requests_write("X0", &expand));
        assert!(calls.get() <= 41 + 6, "{} expansions", calls.get());
    }

    #[test]
    fn rows_match_the_macro_and_both_entry_points() {
        for name in ["RegSetValueEx", "RegSetValueExA", "RegSetValueExW"] {
            assert_eq!(root_key_call(name), Some(RegistryAccess::Writes), "{name}");
        }
        assert_eq!(
            root_key_call("RegOpenKeyExW"),
            Some(RegistryAccess::MaskAt(3))
        );
        assert_eq!(root_key_call("RegSetValueExX"), None);
        assert_eq!(root_key_call("RegQueryValueExA"), None);
    }
}
