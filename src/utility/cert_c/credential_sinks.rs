// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! Declared credential sinks: the library calls whose contract says an
//! argument IS a secret (a password, a passphrase, plaintext handed to a
//! memory-protection call), plus the calls that lock a buffer's pages into
//! memory, the allocators that hand back locked or unlocked pages, and the
//! calls that release them.
//!
//! A buffer is sensitive when it reaches one of these arguments. That is the
//! definition MEM06-C's Juliet cases use ("use the password in LogonUser()
//! to establish that it is sensitive"), and it replaces every guess from a
//! variable's name: a `secret` that never reaches a sink is not shown to hold
//! anything, and a `buf` that reaches `crypt` is.
//!
//! Each row is a platform or library contract (ADR-0015): it states what a
//! named Win32, POSIX, PAM, database, LDAP or crypto-library API does with
//! one argument, and holds only where that API is the one called. A project
//! that defines its own function of the same name is not calling the
//! library, so callers consult the project's function summaries first and
//! these tables only for a callee the project does not define.
//!
//! Shared by MEM06-C (sensitive data kept out of swap and core dumps) and
//! meant for MEM03-C (clearing) and MSC41-C (hard-coded credentials), which
//! select rows by [`SinkKind`] and read [`CredentialSink::len_arg`] for the
//! extent. Declared credential SOURCES (`getpass`, `pam_get_authtok`, ...)
//! are not here yet; MEM03-C's rewrite adds them.

/// What a sink argument receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkKind {
    /// A password or passphrase used to authenticate or derive a key.
    Credential,
    /// Plaintext the call protects (`CryptProtectMemory`'s buffer): secret,
    /// but not a credential, so a hard-coded-credential rule skips it.
    ProtectedPlaintext,
}

/// One argument of a library call that receives a secret.
#[derive(Debug, Clone, Copy)]
pub struct CredentialSink {
    /// The callee, as spelled at the call.
    pub function: &'static str,
    /// Zero-based index of the argument that receives the secret.
    pub arg: usize,
    /// When set, the row applies only if argument `.0` is spelled exactly as
    /// one of `.1` (`pam_set_item`'s item type selects what its item is).
    /// Compared as raw argument text, so an item type held in a variable, or
    /// spelled through a macro, is missed: false negatives only.
    pub when_arg: Option<(usize, &'static [&'static str])>,
    /// Zero-based index of the argument giving the secret's length, when the
    /// call takes one; `None` for a NUL-terminated secret.
    pub len_arg: Option<usize>,
    /// What the argument receives.
    pub kind: SinkKind,
    /// The documentation the row rests on.
    pub basis: &'static str,
}

const PAM_AUTHTOK_ITEMS: &[&str] = &["PAM_AUTHTOK", "PAM_OLDAUTHTOK"];
const LDAP_SIMPLE_METHOD: &[&str] = &["LDAP_AUTH_SIMPLE"];

/// Every declared credential sink.
pub static CREDENTIAL_SINKS: &[CredentialSink] = &[
    // Win32 advapi32: lpszPassword is the account's cleartext password.
    // `LogonUser`/`LogonUserEx` are the <windows.h> macros over the A/W
    // pair, written unsuffixed in most code.
    CredentialSink {
        function: "LogonUserA",
        arg: 2,
        when_arg: None,
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "Win32 LogonUserA: lpszPassword",
    },
    CredentialSink {
        function: "LogonUserW",
        arg: 2,
        when_arg: None,
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "Win32 LogonUserW: lpszPassword",
    },
    CredentialSink {
        function: "LogonUser",
        arg: 2,
        when_arg: None,
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "Win32 LogonUser (<windows.h> macro): lpszPassword",
    },
    CredentialSink {
        function: "LogonUserExA",
        arg: 2,
        when_arg: None,
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "Win32 LogonUserExA: lpszPassword",
    },
    CredentialSink {
        function: "LogonUserExW",
        arg: 2,
        when_arg: None,
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "Win32 LogonUserExW: lpszPassword",
    },
    CredentialSink {
        function: "LogonUserEx",
        arg: 2,
        when_arg: None,
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "Win32 LogonUserEx (<windows.h> macro): lpszPassword",
    },
    CredentialSink {
        function: "CreateProcessWithLogonW",
        arg: 2,
        when_arg: None,
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "Win32 CreateProcessWithLogonW: lpPassword",
    },
    // Win32 dpapi: the buffer CryptProtectMemory encrypts in place is, by
    // the call's purpose, data the caller must keep secret. It is not a
    // credential: a rule about hard-coded credentials must skip this kind.
    CredentialSink {
        function: "CryptProtectMemory",
        arg: 0,
        when_arg: None,
        len_arg: Some(1),
        kind: SinkKind::ProtectedPlaintext,
        basis: "Win32 CryptProtectMemory: pDataIn, cbDataIn",
    },
    // POSIX crypt(3) and its reentrant variants: `key` is the passphrase.
    CredentialSink {
        function: "crypt",
        arg: 0,
        when_arg: None,
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "POSIX.1-2024 crypt: key",
    },
    CredentialSink {
        function: "crypt_r",
        arg: 0,
        when_arg: None,
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "libxcrypt/glibc crypt_r: phrase",
    },
    CredentialSink {
        function: "crypt_rn",
        arg: 0,
        when_arg: None,
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "libxcrypt crypt_rn: phrase",
    },
    CredentialSink {
        function: "crypt_ra",
        arg: 0,
        when_arg: None,
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "libxcrypt crypt_ra: phrase",
    },
    // Linux-PAM / OpenPAM: PAM_AUTHTOK and PAM_OLDAUTHTOK items are the
    // user's current and previous authentication tokens.
    CredentialSink {
        function: "pam_set_item",
        arg: 2,
        when_arg: Some((1, PAM_AUTHTOK_ITEMS)),
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "pam_set_item(3): PAM_AUTHTOK / PAM_OLDAUTHTOK",
    },
    // Database and directory logins: the password parameter of each call.
    CredentialSink {
        function: "mysql_real_connect",
        arg: 3,
        when_arg: None,
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "MySQL C API mysql_real_connect: passwd",
    },
    CredentialSink {
        function: "PQsetdbLogin",
        arg: 6,
        when_arg: None,
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "libpq PQsetdbLogin: pwd",
    },
    CredentialSink {
        function: "ldap_simple_bind_s",
        arg: 2,
        when_arg: None,
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "OpenLDAP ldap_simple_bind_s: passwd",
    },
    CredentialSink {
        function: "ldap_simple_bind",
        arg: 2,
        when_arg: None,
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "OpenLDAP ldap_simple_bind: passwd",
    },
    CredentialSink {
        function: "ldap_bind_s",
        arg: 2,
        when_arg: Some((3, LDAP_SIMPLE_METHOD)),
        len_arg: None,
        kind: SinkKind::Credential,
        basis: "OpenLDAP ldap_bind_s with LDAP_AUTH_SIMPLE: cred is the password",
    },
    // Password hashing and key derivation: the password argument.
    CredentialSink {
        function: "crypto_pwhash_str",
        arg: 1,
        when_arg: None,
        len_arg: Some(2),
        kind: SinkKind::Credential,
        basis: "libsodium crypto_pwhash_str: passwd, passwdlen",
    },
    CredentialSink {
        function: "crypto_pwhash_str_verify",
        arg: 1,
        when_arg: None,
        len_arg: Some(2),
        kind: SinkKind::Credential,
        basis: "libsodium crypto_pwhash_str_verify: passwd, passwdlen",
    },
    CredentialSink {
        function: "crypto_pwhash",
        arg: 2,
        when_arg: None,
        len_arg: Some(3),
        kind: SinkKind::Credential,
        basis: "libsodium crypto_pwhash: passwd, passwdlen",
    },
    CredentialSink {
        function: "PKCS5_PBKDF2_HMAC",
        arg: 0,
        when_arg: None,
        len_arg: Some(1),
        kind: SinkKind::Credential,
        basis: "OpenSSL PKCS5_PBKDF2_HMAC: pass, passlen",
    },
    CredentialSink {
        function: "PKCS5_PBKDF2_HMAC_SHA1",
        arg: 0,
        when_arg: None,
        len_arg: Some(1),
        kind: SinkKind::Credential,
        basis: "OpenSSL PKCS5_PBKDF2_HMAC_SHA1: pass, passlen",
    },
    CredentialSink {
        function: "mbedtls_pkcs5_pbkdf2_hmac_ext",
        arg: 1,
        when_arg: None,
        len_arg: Some(2),
        kind: SinkKind::Credential,
        basis: "Mbed TLS mbedtls_pkcs5_pbkdf2_hmac_ext: password, plen",
    },
    CredentialSink {
        function: "mbedtls_pkcs5_pbkdf2_hmac",
        arg: 1,
        when_arg: None,
        len_arg: Some(2),
        kind: SinkKind::Credential,
        basis: "Mbed TLS mbedtls_pkcs5_pbkdf2_hmac: password, plen",
    },
];

/// Calls that lock the pages of the buffer passed as their first argument
/// into physical memory, so the buffer cannot be written to swap.
const PAGE_LOCK_FUNCS: &[&str] = &["mlock", "mlock2", "VirtualLock", "sodium_mlock"];

/// Allocators whose block is locked (or kept out of swap and core dumps) by
/// construction: libsodium's guarded allocations are `mlock`ed, OpenSSL's
/// and libgcrypt's secure heaps are locked pools.
const LOCKED_ALLOCATORS: &[&str] = &[
    "sodium_malloc",
    "sodium_allocarray",
    "OPENSSL_secure_malloc",
    "OPENSSL_secure_zalloc",
    "gcry_malloc_secure",
    "gcry_calloc_secure",
    "gcry_xmalloc_secure",
    "gcry_xcalloc_secure",
];

/// Platform allocators beyond the C library's whose block is ordinary
/// pageable memory until something locks it.
const UNLOCKED_PLATFORM_ALLOCATORS: &[&str] = &[
    "VirtualAlloc",
    "VirtualAllocEx",
    "HeapAlloc",
    "LocalAlloc",
    "GlobalAlloc",
];

/// Calls that release a block, with the argument that names it.
const RELEASES: &[(&str, usize)] = &[
    ("free", 0),
    ("sodium_free", 0),
    ("OPENSSL_free", 0),
    ("OPENSSL_clear_free", 0),
    ("OPENSSL_secure_free", 0),
    ("OPENSSL_secure_clear_free", 0),
    ("gcry_free", 0),
    ("VirtualFree", 0),
    ("HeapFree", 2),
    ("LocalFree", 0),
    ("GlobalFree", 0),
];

/// Whether argument `arg` of `function` is a credential sink regardless of
/// the call's other arguments. Rows with a `when_arg` condition need the
/// call itself; see [`sink_args_of_call`].
pub fn is_unconditional_sink_arg(function: &str, arg: usize) -> bool {
    CREDENTIAL_SINKS
        .iter()
        .any(|s| s.function == function && s.arg == arg && s.when_arg.is_none())
}

/// Whether `function` has a credential-sink row that needs the call's other
/// arguments to decide (`pam_set_item`, `ldap_bind_s`).
pub fn has_conditional_sink_row(function: &str) -> bool {
    CREDENTIAL_SINKS
        .iter()
        .any(|s| s.function == function && s.when_arg.is_some())
}

/// Whether `function` has any credential-sink row.
pub fn is_credential_sink_function(function: &str) -> bool {
    CREDENTIAL_SINKS.iter().any(|s| s.function == function)
}

/// The rows of one call to `function` that apply, given the call's
/// arguments as source text (trimmed, in order).
pub fn sink_rows_of_call<'a>(
    function: &'a str,
    args: &'a [&'a str],
) -> impl Iterator<Item = &'static CredentialSink> + 'a {
    CREDENTIAL_SINKS
        .iter()
        .filter(move |s| s.function == function && s.arg < args.len())
        .filter(move |s| match s.when_arg {
            None => true,
            Some((i, spellings)) => args.get(i).is_some_and(|a| spellings.contains(a)),
        })
}

/// The argument indices of one call to `function` that receive a secret,
/// given the call's arguments as source text (trimmed, in order).
pub fn sink_args_of_call(function: &str, args: &[&str]) -> Vec<usize> {
    sink_rows_of_call(function, args).map(|s| s.arg).collect()
}

/// Whether `function` locks the pages of its first argument into memory.
pub fn is_page_lock_call(function: &str) -> bool {
    PAGE_LOCK_FUNCS.contains(&function)
}

/// Whether `function` allocates a block, and if so whether the block comes
/// back locked: `Some(true)` for a secure allocator, `Some(false)` for a
/// Win32 allocator of pageable memory, `None` otherwise. The C library's own
/// allocators are `call_roles::is_allocator_call`'s.
pub fn platform_allocation_is_locked(function: &str) -> Option<bool> {
    if LOCKED_ALLOCATORS.contains(&function) {
        Some(true)
    } else if UNLOCKED_PLATFORM_ALLOCATORS.contains(&function) {
        Some(false)
    } else {
        None
    }
}

/// The argument of a call to `function` that names the block it releases.
pub fn released_arg(function: &str) -> Option<usize> {
    RELEASES
        .iter()
        .find(|(name, _)| *name == function)
        .map(|(_, arg)| *arg)
}
