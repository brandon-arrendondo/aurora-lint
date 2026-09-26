// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! Declared credential sinks: the library calls whose contract says an
//! argument IS a secret (a password, a passphrase, plaintext handed to a
//! memory-protection call), and the calls that lock a buffer's pages into
//! memory.
//!
//! A buffer is sensitive when it reaches one of these arguments. That is the
//! definition MEM06-C's Juliet cases use ("use the password in LogonUser()
//! to establish that it is sensitive"), and it replaces every guess from a
//! variable's name: a `secret` that never reaches a sink is not shown to hold
//! anything, and a `buf` that reaches `crypt` is.
//!
//! The table is a set of platform contracts (ADR-0015): each row states what
//! a named platform or library API does with one argument, and holds only where
//! that API is the one called. A project that defines its own function of
//! the same name is not calling the library, so callers consult the
//! project's function summaries first and this table only for a callee the
//! project does not define.
//!
//! Shared by MEM06-C (sensitive data kept out of swap and core dumps) and
//! meant for every rule that asks whether a buffer holds a credential.

/// One argument of a library call that receives a secret.
#[derive(Debug, Clone, Copy)]
pub struct CredentialSink {
    /// The callee, as spelled at the call.
    pub function: &'static str,
    /// Zero-based index of the argument that receives the secret.
    pub arg: usize,
    /// When set, the row applies only if argument `.0` is spelled as one of
    /// `.1` (`pam_set_item`'s item type selects what its item is).
    pub when_arg: Option<(usize, &'static [&'static str])>,
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
        basis: "Win32 LogonUserA: lpszPassword",
    },
    CredentialSink {
        function: "LogonUserW",
        arg: 2,
        when_arg: None,
        basis: "Win32 LogonUserW: lpszPassword",
    },
    CredentialSink {
        function: "LogonUser",
        arg: 2,
        when_arg: None,
        basis: "Win32 LogonUser (<windows.h> macro): lpszPassword",
    },
    CredentialSink {
        function: "LogonUserExA",
        arg: 2,
        when_arg: None,
        basis: "Win32 LogonUserExA: lpszPassword",
    },
    CredentialSink {
        function: "LogonUserExW",
        arg: 2,
        when_arg: None,
        basis: "Win32 LogonUserExW: lpszPassword",
    },
    CredentialSink {
        function: "LogonUserEx",
        arg: 2,
        when_arg: None,
        basis: "Win32 LogonUserEx (<windows.h> macro): lpszPassword",
    },
    CredentialSink {
        function: "CreateProcessWithLogonW",
        arg: 2,
        when_arg: None,
        basis: "Win32 CreateProcessWithLogonW: lpPassword",
    },
    // Win32 dpapi: the buffer CryptProtectMemory encrypts in place is, by
    // the call's purpose, data the caller must keep secret.
    CredentialSink {
        function: "CryptProtectMemory",
        arg: 0,
        when_arg: None,
        basis: "Win32 CryptProtectMemory: pDataIn",
    },
    // POSIX crypt(3) and its reentrant variants: `key` is the passphrase.
    CredentialSink {
        function: "crypt",
        arg: 0,
        when_arg: None,
        basis: "POSIX.1-2024 crypt: key",
    },
    CredentialSink {
        function: "crypt_r",
        arg: 0,
        when_arg: None,
        basis: "libxcrypt/glibc crypt_r: phrase",
    },
    CredentialSink {
        function: "crypt_rn",
        arg: 0,
        when_arg: None,
        basis: "libxcrypt crypt_rn: phrase",
    },
    CredentialSink {
        function: "crypt_ra",
        arg: 0,
        when_arg: None,
        basis: "libxcrypt crypt_ra: phrase",
    },
    // Linux-PAM / OpenPAM: PAM_AUTHTOK and PAM_OLDAUTHTOK items are the
    // user's current and previous authentication tokens.
    CredentialSink {
        function: "pam_set_item",
        arg: 2,
        when_arg: Some((1, PAM_AUTHTOK_ITEMS)),
        basis: "pam_set_item(3): PAM_AUTHTOK / PAM_OLDAUTHTOK",
    },
    // Database and directory logins: the password parameter of each call.
    CredentialSink {
        function: "mysql_real_connect",
        arg: 3,
        when_arg: None,
        basis: "MySQL C API mysql_real_connect: passwd",
    },
    CredentialSink {
        function: "PQsetdbLogin",
        arg: 6,
        when_arg: None,
        basis: "libpq PQsetdbLogin: pwd",
    },
    CredentialSink {
        function: "ldap_simple_bind_s",
        arg: 2,
        when_arg: None,
        basis: "OpenLDAP ldap_simple_bind_s: passwd",
    },
    CredentialSink {
        function: "ldap_simple_bind",
        arg: 2,
        when_arg: None,
        basis: "OpenLDAP ldap_simple_bind: passwd",
    },
    CredentialSink {
        function: "ldap_bind_s",
        arg: 2,
        when_arg: Some((3, LDAP_SIMPLE_METHOD)),
        basis: "OpenLDAP ldap_bind_s with LDAP_AUTH_SIMPLE: cred is the password",
    },
    // Password hashing and key derivation: the password argument.
    CredentialSink {
        function: "crypto_pwhash_str",
        arg: 1,
        when_arg: None,
        basis: "libsodium crypto_pwhash_str: passwd",
    },
    CredentialSink {
        function: "crypto_pwhash_str_verify",
        arg: 1,
        when_arg: None,
        basis: "libsodium crypto_pwhash_str_verify: passwd",
    },
    CredentialSink {
        function: "crypto_pwhash",
        arg: 2,
        when_arg: None,
        basis: "libsodium crypto_pwhash: passwd",
    },
    CredentialSink {
        function: "PKCS5_PBKDF2_HMAC",
        arg: 0,
        when_arg: None,
        basis: "OpenSSL PKCS5_PBKDF2_HMAC: pass",
    },
    CredentialSink {
        function: "PKCS5_PBKDF2_HMAC_SHA1",
        arg: 0,
        when_arg: None,
        basis: "OpenSSL PKCS5_PBKDF2_HMAC_SHA1: pass",
    },
    CredentialSink {
        function: "mbedtls_pkcs5_pbkdf2_hmac_ext",
        arg: 1,
        when_arg: None,
        basis: "Mbed TLS mbedtls_pkcs5_pbkdf2_hmac_ext: password",
    },
    CredentialSink {
        function: "mbedtls_pkcs5_pbkdf2_hmac",
        arg: 1,
        when_arg: None,
        basis: "Mbed TLS mbedtls_pkcs5_pbkdf2_hmac: password",
    },
];

/// Calls that lock the pages of the buffer passed as their first argument
/// into physical memory, so the buffer cannot be written to swap.
const PAGE_LOCK_FUNCS: &[&str] = &["mlock", "mlock2", "VirtualLock"];

/// Whether argument `arg` of `function` is a credential sink regardless of
/// the call's other arguments. Rows with a `when_arg` condition need the
/// call itself; see [`sink_args_of_call`].
pub fn is_unconditional_sink_arg(function: &str, arg: usize) -> bool {
    CREDENTIAL_SINKS
        .iter()
        .any(|s| s.function == function && s.arg == arg && s.when_arg.is_none())
}

/// Whether `function` has any credential-sink row.
pub fn is_credential_sink_function(function: &str) -> bool {
    CREDENTIAL_SINKS.iter().any(|s| s.function == function)
}

/// The argument indices of one call to `function` that receive a secret,
/// given the call's arguments as source text (trimmed, in order).
pub fn sink_args_of_call(function: &str, args: &[&str]) -> Vec<usize> {
    CREDENTIAL_SINKS
        .iter()
        .filter(|s| s.function == function && s.arg < args.len())
        .filter(|s| match s.when_arg {
            None => true,
            Some((i, spellings)) => args.get(i).is_some_and(|a| spellings.contains(a)),
        })
        .map(|s| s.arg)
        .collect()
}

/// Whether `function` locks the pages of its first argument into memory.
pub fn is_page_lock_call(function: &str) -> bool {
    PAGE_LOCK_FUNCS.contains(&function)
}
