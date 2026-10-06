//! Whether this process scans a declared closed program: the
//! `closed_program` environment contract.
//!
//! Undeclared, a function with external linkage has callers the scan cannot
//! see -- a library exports it, `-rdynamic` exports it from an executable --
//! so its in-tree call sites prove nothing about its parameters (ADR-0011).
//! Declared, the scanned files are the whole program, so the in-tree call
//! sites are all of them and a caller-set proof holds for such a function as
//! it does for a `static` one. The function summaries record that while the
//! prescan builds them ([`crate::analyze::function_summary::close_declared_caller_sets`]),
//! so, like the allocator declarations, it is installed once, before prescan.

use anyhow::{bail, Result};
use std::sync::OnceLock;

static DECLARED: OnceLock<bool> = OnceLock::new();

/// Install whether this process scans a declared closed program. Call once,
/// before prescan: the caller-set proofs aggregated there read it, so a
/// declaration made afterwards would reach some tables and not others.
///
/// # Errors
///
/// If the other value is already in force. One process scans under one
/// declaration; repeating the same one is fine.
pub fn declare(closed: bool) -> Result<()> {
    match DECLARED.set(closed) {
        Ok(()) => Ok(()),
        Err(rejected) if DECLARED.get() == Some(&rejected) => Ok(()),
        Err(_) => bail!(
            "a different closed_program declaration is already in force for this process; \
             one process scans under one"
        ),
    }
}

/// Whether a closed program is declared; false until [`declare`] says so.
pub fn declared() -> bool {
    DECLARED.get().copied().unwrap_or(false)
}
