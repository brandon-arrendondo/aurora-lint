//! Thread-API families a project declares: the `[environment.threads]` table.
//!
//! The concurrency rules read a hazard, not an API (`docs/design/thread-api-families.md`):
//! "a condition wait that can wake spuriously sits outside a loop" holds for
//! `cnd_wait`, `pthread_cond_wait` and an RTOS's own wait alike. A rule asks
//! [`crate::utility::cert_c::thread_api`] which operation a call performs, and
//! that module answers from three sources:
//!
//! - C11 `<threads.h>`, always;
//! - POSIX threads, unless the project says it is not POSIX
//!   (`posix_version = "none"`, or `posix = "off"` here);
//! - what the project declares here: shipped RTOS profiles named in
//!   `families`, and its own functions under `functions` and `types`.
//!
//! A built-in name cannot be declared: its contract is the library's
//! (ADR-0015), the same refusal `[environment.allocators]` makes. One process
//! scans under one set of declarations; [`declare`] installs it before the
//! scan.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::OnceLock;

/// What a thread-API call does, read at the level of the hazard a rule names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadOpKind {
    /// Starts a thread running `entry`.
    ThreadCreate,
    /// Waits for the thread `handle` to finish.
    ThreadJoin,
    /// Gives up the right to join the thread `handle`.
    ThreadDetach,
    /// Names the calling thread.
    ThreadSelf,
    /// Ends the calling thread.
    ThreadExit,
    /// Initializes the mutex `object` (or returns a new one).
    MutexInit,
    /// Locks the mutex `object`.
    MutexLock,
    /// Unlocks the mutex `object`.
    MutexUnlock,
    /// Destroys the mutex `object`.
    MutexDestroy,
    /// Waits on the condition `cond`, releasing `mutex` meanwhile.
    CondWait,
    /// Wakes one waiter on `cond`.
    CondSignal,
    /// Wakes every waiter on `cond`.
    CondBroadcast,
    /// Creates the thread-specific storage key `key`, with `destructor`.
    TssCreate,
    /// Stores `value` under the key or slot `key`.
    TssSet,
    /// Reads the value under the key or slot `key`.
    TssGet,
    /// Deletes the key `key`.
    TssDelete,
    /// Runs `function` once for the flag `flag`.
    Once,
    /// Suspends the calling thread for a time.
    Sleep,
}

impl ThreadOpKind {
    /// Every kind, in the order they are listed to a user.
    pub const ALL: [ThreadOpKind; 18] = [
        Self::ThreadCreate,
        Self::ThreadJoin,
        Self::ThreadDetach,
        Self::ThreadSelf,
        Self::ThreadExit,
        Self::MutexInit,
        Self::MutexLock,
        Self::MutexUnlock,
        Self::MutexDestroy,
        Self::CondWait,
        Self::CondSignal,
        Self::CondBroadcast,
        Self::TssCreate,
        Self::TssSet,
        Self::TssGet,
        Self::TssDelete,
        Self::Once,
        Self::Sleep,
    ];

    /// The name a declaration spells it with.
    pub fn name(self) -> &'static str {
        match self {
            Self::ThreadCreate => "thread_create",
            Self::ThreadJoin => "thread_join",
            Self::ThreadDetach => "thread_detach",
            Self::ThreadSelf => "thread_self",
            Self::ThreadExit => "thread_exit",
            Self::MutexInit => "mutex_init",
            Self::MutexLock => "mutex_lock",
            Self::MutexUnlock => "mutex_unlock",
            Self::MutexDestroy => "mutex_destroy",
            Self::CondWait => "cond_wait",
            Self::CondSignal => "cond_signal",
            Self::CondBroadcast => "cond_broadcast",
            Self::TssCreate => "tss_create",
            Self::TssSet => "tss_set",
            Self::TssGet => "tss_get",
            Self::TssDelete => "tss_delete",
            Self::Once => "once",
            Self::Sleep => "sleep",
        }
    }

    /// The operand roles a declaration of this kind may give, and which of
    /// them it must.
    fn roles(self) -> (&'static [Role], &'static [Role]) {
        use Role::*;
        match self {
            Self::ThreadCreate => (&[Entry, Arg, Handle], &[Entry]),
            Self::ThreadJoin | Self::ThreadDetach => (&[Handle], &[]),
            Self::ThreadSelf | Self::ThreadExit | Self::Sleep => (&[], &[]),
            Self::MutexInit | Self::MutexUnlock | Self::MutexDestroy => (&[Object], &[]),
            Self::MutexLock => (&[Object, Blocking], &[]),
            Self::CondWait => (&[Cond, Mutex, Spurious], &[Spurious]),
            Self::CondSignal | Self::CondBroadcast => (&[Cond], &[]),
            Self::TssCreate => (&[Key, Destructor], &[Key]),
            Self::TssSet => (&[Key, Value, Destructor], &[Key]),
            Self::TssGet | Self::TssDelete => (&[Key], &[Key]),
            Self::Once => (&[Flag, Function], &[]),
        }
    }
}

impl fmt::Display for ThreadOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// An operand a declaration places, or a property it states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The thread's entry function.
    Entry,
    /// The argument the entry function receives.
    Arg,
    /// The thread handle.
    Handle,
    /// The mutex.
    Object,
    /// The condition.
    Cond,
    /// The mutex a condition wait releases.
    Mutex,
    /// The thread-specific storage key or slot.
    Key,
    /// The value stored.
    Value,
    /// The destructor run at thread exit.
    Destructor,
    /// The once flag.
    Flag,
    /// The function run once.
    Function,
    /// Whether a lock blocks (`blocking`).
    Blocking,
    /// Whether a wait can wake spuriously (`spurious`).
    Spurious,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::Arg => "arg",
            Self::Handle => "handle",
            Self::Object => "object",
            Self::Cond => "cond",
            Self::Mutex => "mutex",
            Self::Key => "key",
            Self::Value => "value",
            Self::Destructor => "destructor",
            Self::Flag => "flag",
            Self::Function => "function",
            Self::Blocking => "blocking",
            Self::Spurious => "spurious",
        }
    }
}

/// Whether a lock call blocks until the mutex is free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Blocking {
    /// Until it gets the mutex (`mtx_lock`).
    Always,
    /// Until it gets the mutex or a timeout passes (`mtx_timedlock`).
    Timeout,
    /// Never: it fails at once if the mutex is held (`mtx_trylock`).
    Never,
}

/// One function's thread-API contract: its kind, and the 1-based argument
/// positions of its operands. What a `[environment.threads.functions]` entry
/// spells as an inline table, and what the built-in tables hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadOp {
    /// What the call does.
    pub op: ThreadOpKind,
    /// The thread's entry function.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<usize>,
    /// The argument the entry function receives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg: Option<usize>,
    /// The thread handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<usize>,
    /// The mutex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<usize>,
    /// The condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cond: Option<usize>,
    /// The mutex a condition wait releases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutex: Option<usize>,
    /// The thread-specific storage key, or a slot index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<usize>,
    /// The value stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<usize>,
    /// The destructor run at thread exit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructor: Option<usize>,
    /// The once flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flag: Option<usize>,
    /// The function run once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<usize>,
    /// The exact argument count. A call with another count is a different
    /// function of the same name and is not this operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arity: Option<usize>,
    /// Whether a lock blocks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking: Option<Blocking>,
    /// Whether a condition wait can return without a signal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spurious: Option<bool>,
}

impl ThreadOp {
    /// A contract of `op` that places no operand, for the built-in tables to
    /// fill in with struct-update syntax.
    pub const fn of(op: ThreadOpKind) -> Self {
        Self {
            op,
            entry: None,
            arg: None,
            handle: None,
            object: None,
            cond: None,
            mutex: None,
            key: None,
            value: None,
            destructor: None,
            flag: None,
            function: None,
            arity: None,
            blocking: None,
            spurious: None,
        }
    }

    /// The 1-based position of `role`'s operand, if this contract places it.
    pub fn position(&self, role: Role) -> Option<usize> {
        match role {
            Role::Entry => self.entry,
            Role::Arg => self.arg,
            Role::Handle => self.handle,
            Role::Object => self.object,
            Role::Cond => self.cond,
            Role::Mutex => self.mutex,
            Role::Key => self.key,
            Role::Value => self.value,
            Role::Destructor => self.destructor,
            Role::Flag => self.flag,
            Role::Function => self.function,
            Role::Blocking | Role::Spurious => None,
        }
    }

    fn gives(&self, role: Role) -> bool {
        match role {
            Role::Blocking => self.blocking.is_some(),
            Role::Spurious => self.spurious.is_some(),
            _ => self.position(role).is_some(),
        }
    }

    const ROLES: [Role; 13] = [
        Role::Entry,
        Role::Arg,
        Role::Handle,
        Role::Object,
        Role::Cond,
        Role::Mutex,
        Role::Key,
        Role::Value,
        Role::Destructor,
        Role::Flag,
        Role::Function,
        Role::Blocking,
        Role::Spurious,
    ];

    /// Refuse a contract that cannot mean what it says: a role its kind does
    /// not take, a required role left out, a position below 1, or one past
    /// the stated arity.
    fn validate(&self, name: &str) -> Result<()> {
        let (allowed, required) = self.op.roles();
        for role in Self::ROLES {
            if self.gives(role) && !allowed.contains(&role) {
                bail!(
                    "[environment.threads.functions]: '{name}' is a {} and takes no '{}'; \
                     allowed: {}",
                    self.op,
                    role.name(),
                    role_list(allowed)
                );
            }
        }
        for role in required {
            if !self.gives(*role) {
                bail!(
                    "[environment.threads.functions]: '{name}' is a {} and must give '{}'",
                    self.op,
                    role.name()
                );
            }
        }
        for role in Self::ROLES {
            if let Some(position) = self.position(role) {
                if position == 0 {
                    bail!(
                        "[environment.threads.functions]: '{name}' places '{}' at argument 0; \
                         positions count from 1",
                        role.name()
                    );
                }
                if self.arity.is_some_and(|arity| position > arity) {
                    bail!(
                        "[environment.threads.functions]: '{name}' places '{}' at argument \
                         {position}, past its arity {}",
                        role.name(),
                        self.arity.unwrap_or_default()
                    );
                }
            }
        }
        Ok(())
    }
}

fn role_list(roles: &[Role]) -> String {
    if roles.is_empty() {
        return "none".to_string();
    }
    let mut names: Vec<&str> = roles.iter().map(|r| r.name()).collect();
    names.push("arity");
    names.join(", ")
}

/// What a declared type is, for the rules that ask what an object holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadTypeKind {
    /// A thread handle (`thrd_t`).
    Thread,
    /// A mutex (`mtx_t`).
    Mutex,
    /// A condition (`cnd_t`).
    Cond,
    /// A thread-specific storage key (`tss_t`).
    TssKey,
    /// A once flag (`once_flag`).
    OnceFlag,
}

/// A thread-API family shipped in-tree, selected by name in `families`.
/// Each states the version of the API it was checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// FreeRTOS, checked against FreeRTOS-Kernel V11.2.0.
    Freertos,
}

impl Profile {
    /// The name `families` spells it with.
    pub fn name(self) -> &'static str {
        match self {
            Self::Freertos => "freertos",
        }
    }
}

/// Whether the POSIX threads family is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PosixFamily {
    /// Read unless `posix_version = "none"` says the target is not POSIX.
    #[default]
    Auto,
    /// Not read: a `pthread_*` call is an unknown function.
    Off,
}

/// The `[environment.threads]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadsConfig {
    /// Shipped profiles to read, by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub families: Vec<Profile>,
    /// Whether the POSIX family is read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posix: Option<PosixFamily>,
    /// The project's own functions, by name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub functions: BTreeMap<String, ThreadOp>,
    /// The project's own types, by name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub types: BTreeMap<String, ThreadTypeKind>,
}

impl ThreadsConfig {
    /// Whether the table says nothing.
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Layer `other` over `self`: its families join, its `posix` wins, and
    /// its functions and types win per name.
    pub fn overlay(&mut self, other: &ThreadsConfig) {
        for family in &other.families {
            if !self.families.contains(family) {
                self.families.push(*family);
            }
        }
        if other.posix.is_some() {
            self.posix = other.posix;
        }
        self.functions
            .extend(other.functions.iter().map(|(k, v)| (k.clone(), *v)));
        self.types
            .extend(other.types.iter().map(|(k, v)| (k.clone(), *v)));
    }
}

/// The declarations in force, resolved from `[environment.threads]` and
/// `posix_version`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadDeclarations {
    /// Whether the POSIX family is read.
    pub posix: bool,
    /// The shipped profiles read.
    pub families: BTreeSet<Profile>,
    /// The project's own functions.
    pub functions: BTreeMap<String, ThreadOp>,
    /// The project's own types.
    pub types: BTreeMap<String, ThreadTypeKind>,
}

impl Default for ThreadDeclarations {
    fn default() -> Self {
        Self {
            posix: true,
            families: BTreeSet::new(),
            functions: BTreeMap::new(),
            types: BTreeMap::new(),
        }
    }
}

impl ThreadDeclarations {
    /// Resolve `config` under the declared POSIX edition: the POSIX family is
    /// read unless the table turns it off or the target is declared not
    /// POSIX.
    pub fn resolve(
        config: Option<&ThreadsConfig>,
        posix_version: Option<super::PosixVersion>,
    ) -> Result<Self> {
        let config = config.cloned().unwrap_or_default();
        let declarations = Self {
            posix: config.posix != Some(PosixFamily::Off)
                && posix_version != Some(super::PosixVersion::None),
            families: config.families.into_iter().collect(),
            functions: config.functions,
            types: config.types,
        };
        declarations.validate()?;
        Ok(declarations)
    }

    /// Whether this is the default: POSIX read, nothing declared.
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// Refuse a declaration that cannot mean what it says: a name that is
    /// not a C identifier, a contract its kind contradicts, or a name a
    /// built-in or selected family already defines, whose contract is that
    /// family's.
    pub fn validate(&self) -> Result<()> {
        use crate::utility::cert_c::thread_api;
        for (name, op) in &self.functions {
            if !is_identifier(name) {
                bail!("[environment.threads.functions]: '{name}' is not a C identifier");
            }
            if let Some(family) = thread_api::builtin_family_of(name) {
                bail!(
                    "[environment.threads.functions]: '{name}' is a {family} function; its \
                     contract is the library's, not a declaration"
                );
            }
            if let Some(profile) = self
                .families
                .iter()
                .find(|p| thread_api::profile_op(**p, name).is_some())
            {
                bail!(
                    "[environment.threads.functions]: '{name}' is already declared by the \
                     '{}' family",
                    profile.name()
                );
            }
            op.validate(name)?;
        }
        for name in self.types.keys() {
            if !is_identifier(name) {
                bail!("[environment.threads.types]: '{name}' is not a C identifier");
            }
            if let Some(family) = thread_api::builtin_type_family_of(name) {
                bail!(
                    "[environment.threads.types]: '{name}' is a {family} type; its meaning \
                     is the library's, not a declaration"
                );
            }
        }
        Ok(())
    }
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

static DECLARED: OnceLock<ThreadDeclarations> = OnceLock::new();

/// Install the declarations this process scans under. Call once, before the
/// scan.
///
/// # Errors
///
/// If different declarations are already in force. One process scans under
/// one set; re-declaring the identical set is fine.
pub fn declare(declarations: ThreadDeclarations) -> Result<()> {
    match DECLARED.set(declarations) {
        Ok(()) => Ok(()),
        Err(rejected) if DECLARED.get() == Some(&rejected) => Ok(()),
        Err(_) => bail!(
            "different thread-API declarations are already in force for this process; one \
             process scans under one set"
        ),
    }
}

/// The declarations in force: the default (C11 and POSIX, nothing declared)
/// until [`declare`] installs any.
pub fn declared() -> &'static ThreadDeclarations {
    static DEFAULT: OnceLock<ThreadDeclarations> = OnceLock::new();
    DECLARED
        .get()
        .unwrap_or_else(|| DEFAULT.get_or_init(ThreadDeclarations::default))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(toml_text: &str) -> Result<ThreadDeclarations> {
        let config: ThreadsConfig = toml::from_str(toml_text)?;
        ThreadDeclarations::resolve(Some(&config), None)
    }

    #[test]
    fn a_project_family_parses_and_validates() {
        let d = resolve(
            "families = [\"freertos\"]\n\
             [functions]\n\
             os_lock = { op = \"mutex_lock\", object = 1, blocking = \"always\" }\n\
             os_spawn = { op = \"thread_create\", entry = 2, arg = 3, arity = 5 }\n\
             os_wait = { op = \"cond_wait\", cond = 1, mutex = 2, spurious = true }\n\
             [types]\n\
             os_mutex_t = \"mutex\"\n",
        )
        .unwrap();
        assert!(d.posix);
        assert!(d.families.contains(&Profile::Freertos));
        assert_eq!(d.functions["os_spawn"].entry, Some(2));
        assert_eq!(d.types["os_mutex_t"], ThreadTypeKind::Mutex);
    }

    #[test]
    fn unknown_keys_kinds_and_profiles_are_refused() {
        assert!(toml::from_str::<ThreadsConfig>("famlies = []\n").is_err());
        assert!(toml::from_str::<ThreadsConfig>("families = [\"vxworks\"]\n").is_err());
        assert!(toml::from_str::<ThreadsConfig>("[functions]\nf = { op = \"lock\" }\n").is_err());
        assert!(toml::from_str::<ThreadsConfig>(
            "[functions]\nf = { op = \"mutex_lock\", mutex_arg = 1 }\n"
        )
        .is_err());
    }

    #[test]
    fn a_contract_its_kind_contradicts_is_refused() {
        let missing = resolve("[functions]\nos_spawn = { op = \"thread_create\" }\n").unwrap_err();
        assert!(
            missing.to_string().contains("must give 'entry'"),
            "{missing}"
        );
        let foreign =
            resolve("[functions]\nos_lock = { op = \"mutex_lock\", entry = 1 }\n").unwrap_err();
        assert!(
            foreign.to_string().contains("takes no 'entry'"),
            "{foreign}"
        );
        let zero = resolve("[functions]\nos_lock = { op = \"mutex_lock\", object = 0 }\n");
        assert!(zero.is_err());
        let past =
            resolve("[functions]\nos_spawn = { op = \"thread_create\", entry = 4, arity = 3 }\n");
        assert!(past.is_err());
        let unstated = resolve("[functions]\nos_wait = { op = \"cond_wait\", cond = 1 }\n");
        assert!(
            unstated.is_err(),
            "a wait must say whether it wakes spuriously"
        );
    }

    #[test]
    fn a_built_in_or_profile_name_is_refused() {
        let c11 = resolve("[functions]\ncnd_wait = { op = \"cond_wait\", spurious = false }\n")
            .unwrap_err();
        assert!(c11.to_string().contains("C11"), "{c11}");
        assert!(resolve("[functions]\npthread_mutex_lock = { op = \"mutex_lock\" }\n").is_err());
        assert!(resolve(
            "families = [\"freertos\"]\n[functions]\nxTaskCreate = { op = \"thread_create\", entry = 1 }\n"
        )
        .is_err());
        // Without the profile selected, the name is the project's to declare.
        resolve("[functions]\nxTaskCreate = { op = \"thread_create\", entry = 1 }\n").unwrap();
        assert!(resolve("[types]\nmtx_t = \"mutex\"\n").is_err());
        assert!(resolve("[functions]\n\"os-lock\" = { op = \"mutex_lock\" }\n").is_err());
    }

    #[test]
    fn posix_is_read_unless_turned_off_or_the_target_is_not_posix() {
        assert!(ThreadDeclarations::resolve(None, None).unwrap().posix);
        assert!(
            !ThreadDeclarations::resolve(None, Some(super::super::PosixVersion::None))
                .unwrap()
                .posix
        );
        assert!(!resolve("posix = \"off\"\n").unwrap().posix);
        assert!(resolve("posix = \"auto\"\n").unwrap().posix);
        assert!(ThreadDeclarations::resolve(None, None)
            .unwrap()
            .is_default());
    }
}
