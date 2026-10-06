//! Contain a panic to the one rule and file it happened in.
//!
//! A rule that panics on one construct in one file used to take the whole
//! scan down with it: the panic crossed the rayon worker, `collect` re-raised
//! it on the main thread, and the process exited 101 with no findings at all,
//! not even the ones every other rule had already produced. A bug in one
//! rule's handling of one construct says nothing about the rest of the scan.
//!
//! [`contain`] runs a closure under `catch_unwind` and turns a panic into a
//! [`ScanFailure`], so the caller can record it and go on. A contained
//! failure is never silent: the scan reports each one, and exits with
//! [`EXIT_INCOMPLETE`] instead of any findings-based code, so CI cannot read a
//! partial scan as a clean one.
//!
//! What a contained panic can leave behind. A rule gets a fresh instance per
//! file, so its own state dies with the file. Process-wide `Mutex`es in this
//! crate recover from poisoning (`lock().unwrap_or_else(|e| e.into_inner())`),
//! and a `OnceLock` whose initialiser panicked stays empty and is retried. The
//! one thread-local that carries rows across a rule's call is the
//! deallocator-candidate buffer, which the caller rolls back
//! ([`super::deallocator_candidates::pending_len`]). A per-file cache that a
//! panicking rule had half-filled could still mislead a later rule on the
//! SAME file; that is why a failure names the file as well as the rule.

// Containment needs unwinding: under `panic = "abort"` `catch_unwind` catches
// nothing and a rule's panic ends the scan with no output again.
#[cfg(panic = "abort")]
compile_error!("aurora-lint contains rule panics and must be built with panic = \"unwind\"");

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::panic::{self, AssertUnwindSafe};
use std::sync::Once;

/// The exit status of a scan that completed but contained at least one
/// failure: its output is real but incomplete. Distinct from `1` (findings
/// over a `--fail-on-*` threshold) and `2` (the scan could not run), and
/// takes precedence over `1`.
pub const EXIT_INCOMPLETE: i32 = 3;

/// Where in the scan a contained panic happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// One rule's check of one file. Every other rule's findings for the
    /// file stand.
    Rule,
    /// Reading, parsing or analysing one file before or around its rules:
    /// the file contributes no findings.
    File,
}

/// One contained panic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScanFailure {
    /// Whether one rule or the whole file was lost.
    pub stage: Stage,
    /// The file being analysed.
    pub file: String,
    /// The rule that panicked, for [`Stage::Rule`].
    pub rule_id: Option<String>,
    /// The panic message.
    pub message: String,
    /// Where in aurora-lint's own source it panicked (`file:line:col`).
    pub location: Option<String>,
}

impl ScanFailure {
    /// One line, stable enough for a log scraper: `rule failure: RULE: FILE:
    /// MESSAGE [at LOCATION]` or `file failure: FILE: ...`.
    pub fn render(&self) -> String {
        let at = self
            .location
            .as_deref()
            .map(|l| format!(" [at {l}]"))
            .unwrap_or_default();
        match (&self.stage, &self.rule_id) {
            (Stage::Rule, Some(rule)) => {
                format!("rule failure: {rule}: {}: {}{at}", self.file, self.message)
            }
            _ => format!("file failure: {}: {}{at}", self.file, self.message),
        }
    }
}

thread_local! {
    /// Depth of [`contain`] calls active on this thread.
    static CONTAINING: Cell<usize> = const { Cell::new(0) };
    /// The message and location the hook saw for the panic being contained.
    static CAUGHT: RefCell<Option<(String, Option<String>)>> = const { RefCell::new(None) };
}

/// Install, once per process, a panic hook that stays quiet about a panic
/// [`contain`] is about to catch (the scan reports it as a [`ScanFailure`]
/// instead of the default "thread panicked" text) and defers to the previous
/// hook for every other panic.
fn install_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if CONTAINING.with(|c| c.get()) == 0 {
                previous(info);
                return;
            }
            let location = info
                .location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
            CAUGHT.with(|c| *c.borrow_mut() = Some((payload_text(info.payload()), location)));
        }));
    });
}

fn payload_text(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic with a non-string payload".to_string()
    }
}

/// Run `f`; a panic inside it becomes `Err((message, location))` instead of
/// unwinding further.
///
/// `AssertUnwindSafe` is deliberate: the closures this wraps borrow the
/// file's tree, source and shared context, none of which a check mutates
/// except through the interior-mutability cases the module doc lists.
pub fn contain<R>(f: impl FnOnce() -> R) -> Result<R, (String, Option<String>)> {
    install_hook();
    CONTAINING.with(|c| c.set(c.get() + 1));
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    CONTAINING.with(|c| c.set(c.get() - 1));
    result.map_err(|payload| {
        CAUGHT
            .with(|c| c.borrow_mut().take())
            .unwrap_or_else(|| (payload_text(payload.as_ref()), None))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_passes_through() {
        assert_eq!(contain(|| 7), Ok(7));
    }

    #[test]
    fn a_panic_becomes_its_message_and_location() {
        let (message, location) = contain(|| -> () { panic!("boom {}", 1) }).unwrap_err();
        assert_eq!(message, "boom 1");
        assert!(location.unwrap().contains("containment.rs"));
    }

    #[test]
    fn a_slice_panic_is_contained() {
        let text = String::from("sizeof x) + (y");
        let (open, close) = (text.find('(').unwrap(), text.find(')').unwrap());
        let err = contain(|| text[open + 1..close].len()).unwrap_err();
        assert!(err.0.contains("begin > end"), "{}", err.0);
    }

    #[test]
    fn nesting_keeps_the_hook_quiet_until_the_outermost_returns() {
        let outer = contain(|| contain(|| -> () { panic!("inner") }).unwrap_err().0);
        assert_eq!(outer.unwrap(), "inner");
    }

    #[test]
    fn render_names_rule_and_file() {
        let f = ScanFailure {
            stage: Stage::Rule,
            file: "a.c".into(),
            rule_id: Some("MEM35-C".into()),
            message: "begin > end".into(),
            location: Some("mem35_c.rs:180:50".into()),
        };
        assert_eq!(
            f.render(),
            "rule failure: MEM35-C: a.c: begin > end [at mem35_c.rs:180:50]"
        );
    }
}
