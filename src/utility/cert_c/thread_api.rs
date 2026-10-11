//! Which thread-API operation a call performs: thread create/join/detach,
//! mutex lock/unlock, condition wait/signal, thread-specific storage and the
//! rest of [`ThreadOpKind`], and where its operands are.
//!
//! The concurrency rules read a hazard at the level CERT titles it, not the
//! spelling of one API (`docs/design/thread-api-families.md`). One query
//! serves every family:
//!
//! - C11 `<threads.h>`: always read.
//! - POSIX threads: read unless the project says its target is not POSIX
//!   (`settings::threads`).
//! - Shipped RTOS profiles the project names, and its own declared functions
//!   and types.
//!
//! Identity is by resolution, not spelling alone (ADR-0006). A callee that
//! resolves to a local, a parameter or a file-scope object of that name, such
//! as a function pointer, is that object and performs no operation. A call
//! whose argument count differs from the operation's arity is a different
//! function of the same name. A reserved library name that a project defines
//! itself (a shim implementing `pthread_cond_wait` over another API, say)
//! still names the library's interface, since the standard reserves the name
//! for exactly that contract.

use crate::settings::threads::{
    declared, Blocking, Profile, Role, ThreadOp, ThreadOpKind, ThreadTypeKind,
};
use crate::utility::cert_c::ast_utils::{
    get_node_text, resolve_identifier_binding, IdentifierBinding,
};
use crate::utility::cert_c::node_children::NodeChildren;
use std::fmt;
use tree_sitter::Node;

use ThreadOpKind as K;

const fn op(kind: ThreadOpKind, arity: usize) -> ThreadOp {
    ThreadOp {
        arity: Some(arity),
        ..ThreadOp::of(kind)
    }
}

/// C11 `<threads.h>` (C11 7.26).
const C11_OPS: &[(&str, ThreadOp)] = &[
    (
        "thrd_create",
        ThreadOp {
            handle: Some(1),
            entry: Some(2),
            arg: Some(3),
            ..op(K::ThreadCreate, 3)
        },
    ),
    (
        "thrd_join",
        ThreadOp {
            handle: Some(1),
            ..op(K::ThreadJoin, 2)
        },
    ),
    (
        "thrd_detach",
        ThreadOp {
            handle: Some(1),
            ..op(K::ThreadDetach, 1)
        },
    ),
    ("thrd_current", op(K::ThreadSelf, 0)),
    ("thrd_exit", op(K::ThreadExit, 1)),
    ("thrd_sleep", op(K::Sleep, 2)),
    (
        "mtx_init",
        ThreadOp {
            object: Some(1),
            ..op(K::MutexInit, 2)
        },
    ),
    (
        "mtx_lock",
        ThreadOp {
            object: Some(1),
            blocking: Some(Blocking::Always),
            ..op(K::MutexLock, 1)
        },
    ),
    (
        "mtx_timedlock",
        ThreadOp {
            object: Some(1),
            blocking: Some(Blocking::Timeout),
            ..op(K::MutexLock, 2)
        },
    ),
    (
        "mtx_trylock",
        ThreadOp {
            object: Some(1),
            blocking: Some(Blocking::Never),
            ..op(K::MutexLock, 1)
        },
    ),
    (
        "mtx_unlock",
        ThreadOp {
            object: Some(1),
            ..op(K::MutexUnlock, 1)
        },
    ),
    (
        "mtx_destroy",
        ThreadOp {
            object: Some(1),
            ..op(K::MutexDestroy, 1)
        },
    ),
    (
        "cnd_wait",
        ThreadOp {
            cond: Some(1),
            mutex: Some(2),
            spurious: Some(true),
            ..op(K::CondWait, 2)
        },
    ),
    (
        "cnd_timedwait",
        ThreadOp {
            cond: Some(1),
            mutex: Some(2),
            spurious: Some(true),
            ..op(K::CondWait, 3)
        },
    ),
    (
        "cnd_signal",
        ThreadOp {
            cond: Some(1),
            ..op(K::CondSignal, 1)
        },
    ),
    (
        "cnd_broadcast",
        ThreadOp {
            cond: Some(1),
            ..op(K::CondBroadcast, 1)
        },
    ),
    (
        "tss_create",
        ThreadOp {
            key: Some(1),
            destructor: Some(2),
            ..op(K::TssCreate, 2)
        },
    ),
    (
        "tss_set",
        ThreadOp {
            key: Some(1),
            value: Some(2),
            ..op(K::TssSet, 2)
        },
    ),
    (
        "tss_get",
        ThreadOp {
            key: Some(1),
            ..op(K::TssGet, 1)
        },
    ),
    (
        "tss_delete",
        ThreadOp {
            key: Some(1),
            ..op(K::TssDelete, 1)
        },
    ),
    (
        "call_once",
        ThreadOp {
            flag: Some(1),
            function: Some(2),
            ..op(K::Once, 2)
        },
    ),
];

const C11_TYPES: &[(&str, ThreadTypeKind)] = &[
    ("thrd_t", ThreadTypeKind::Thread),
    ("mtx_t", ThreadTypeKind::Mutex),
    ("cnd_t", ThreadTypeKind::Cond),
    ("tss_t", ThreadTypeKind::TssKey),
    ("once_flag", ThreadTypeKind::OnceFlag),
];

/// POSIX threads (`<pthread.h>`), with the sleeps POSIX adds.
const POSIX_OPS: &[(&str, ThreadOp)] = &[
    (
        "pthread_create",
        ThreadOp {
            handle: Some(1),
            entry: Some(3),
            arg: Some(4),
            ..op(K::ThreadCreate, 4)
        },
    ),
    (
        "pthread_join",
        ThreadOp {
            handle: Some(1),
            ..op(K::ThreadJoin, 2)
        },
    ),
    (
        "pthread_detach",
        ThreadOp {
            handle: Some(1),
            ..op(K::ThreadDetach, 1)
        },
    ),
    ("pthread_self", op(K::ThreadSelf, 0)),
    ("pthread_exit", op(K::ThreadExit, 1)),
    ("nanosleep", op(K::Sleep, 2)),
    ("sleep", op(K::Sleep, 1)),
    ("usleep", op(K::Sleep, 1)),
    (
        "pthread_mutex_init",
        ThreadOp {
            object: Some(1),
            ..op(K::MutexInit, 2)
        },
    ),
    (
        "pthread_mutex_lock",
        ThreadOp {
            object: Some(1),
            blocking: Some(Blocking::Always),
            ..op(K::MutexLock, 1)
        },
    ),
    (
        "pthread_mutex_timedlock",
        ThreadOp {
            object: Some(1),
            blocking: Some(Blocking::Timeout),
            ..op(K::MutexLock, 2)
        },
    ),
    (
        "pthread_mutex_trylock",
        ThreadOp {
            object: Some(1),
            blocking: Some(Blocking::Never),
            ..op(K::MutexLock, 1)
        },
    ),
    (
        "pthread_mutex_unlock",
        ThreadOp {
            object: Some(1),
            ..op(K::MutexUnlock, 1)
        },
    ),
    (
        "pthread_mutex_destroy",
        ThreadOp {
            object: Some(1),
            ..op(K::MutexDestroy, 1)
        },
    ),
    (
        "pthread_cond_wait",
        ThreadOp {
            cond: Some(1),
            mutex: Some(2),
            spurious: Some(true),
            ..op(K::CondWait, 2)
        },
    ),
    (
        "pthread_cond_timedwait",
        ThreadOp {
            cond: Some(1),
            mutex: Some(2),
            spurious: Some(true),
            ..op(K::CondWait, 3)
        },
    ),
    (
        "pthread_cond_clockwait",
        ThreadOp {
            cond: Some(1),
            mutex: Some(2),
            spurious: Some(true),
            ..op(K::CondWait, 4)
        },
    ),
    (
        "pthread_cond_signal",
        ThreadOp {
            cond: Some(1),
            ..op(K::CondSignal, 1)
        },
    ),
    (
        "pthread_cond_broadcast",
        ThreadOp {
            cond: Some(1),
            ..op(K::CondBroadcast, 1)
        },
    ),
    (
        "pthread_key_create",
        ThreadOp {
            key: Some(1),
            destructor: Some(2),
            ..op(K::TssCreate, 2)
        },
    ),
    (
        "pthread_setspecific",
        ThreadOp {
            key: Some(1),
            value: Some(2),
            ..op(K::TssSet, 2)
        },
    ),
    (
        "pthread_getspecific",
        ThreadOp {
            key: Some(1),
            ..op(K::TssGet, 1)
        },
    ),
    (
        "pthread_key_delete",
        ThreadOp {
            key: Some(1),
            ..op(K::TssDelete, 1)
        },
    ),
    (
        "pthread_once",
        ThreadOp {
            flag: Some(1),
            function: Some(2),
            ..op(K::Once, 2)
        },
    ),
];

const POSIX_TYPES: &[(&str, ThreadTypeKind)] = &[
    ("pthread_t", ThreadTypeKind::Thread),
    ("pthread_mutex_t", ThreadTypeKind::Mutex),
    ("pthread_cond_t", ThreadTypeKind::Cond),
    ("pthread_key_t", ThreadTypeKind::TssKey),
    ("pthread_once_t", ThreadTypeKind::OnceFlag),
];

/// FreeRTOS, checked against FreeRTOS-Kernel V11.2.0 (`task.h`, `semphr.h`).
///
/// Left out on purpose:
/// - `xSemaphoreTake`/`xSemaphoreGive` serve binary and counting semaphores
///   as well as mutexes, so a call is a lock only when its handle came from a
///   mutex-creating call. The recursive forms take only a recursive mutex.
/// - `vTaskDelete` ends the caller only when passed `NULL`.
/// - FreeRTOS has no condition variable. A task has no join or detach, and
///   its thread-local storage slots have no destructor.
const FREERTOS_OPS: &[(&str, ThreadOp)] = &[
    (
        "xTaskCreate",
        ThreadOp {
            entry: Some(1),
            arg: Some(4),
            handle: Some(6),
            ..op(K::ThreadCreate, 6)
        },
    ),
    (
        "xTaskCreateStatic",
        ThreadOp {
            entry: Some(1),
            arg: Some(4),
            ..op(K::ThreadCreate, 7)
        },
    ),
    ("xSemaphoreCreateMutex", op(K::MutexInit, 0)),
    ("xSemaphoreCreateRecursiveMutex", op(K::MutexInit, 0)),
    ("xSemaphoreCreateMutexStatic", op(K::MutexInit, 1)),
    ("xSemaphoreCreateRecursiveMutexStatic", op(K::MutexInit, 1)),
    (
        "xSemaphoreTakeRecursive",
        ThreadOp {
            object: Some(1),
            blocking: Some(Blocking::Timeout),
            ..op(K::MutexLock, 2)
        },
    ),
    (
        "xSemaphoreGiveRecursive",
        ThreadOp {
            object: Some(1),
            ..op(K::MutexUnlock, 1)
        },
    ),
    (
        "vTaskSetThreadLocalStoragePointer",
        ThreadOp {
            key: Some(2),
            value: Some(3),
            ..op(K::TssSet, 3)
        },
    ),
    (
        "pvTaskGetThreadLocalStoragePointer",
        ThreadOp {
            key: Some(2),
            ..op(K::TssGet, 2)
        },
    ),
    ("vTaskDelay", op(K::Sleep, 1)),
    ("xTaskDelayUntil", op(K::Sleep, 2)),
    ("vTaskDelayUntil", op(K::Sleep, 2)),
];

const FREERTOS_TYPES: &[(&str, ThreadTypeKind)] = &[("TaskHandle_t", ThreadTypeKind::Thread)];

/// Which family an operation belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// C11 `<threads.h>`.
    C11,
    /// POSIX threads.
    Posix,
    /// A shipped profile the project selected.
    Profile(Profile),
    /// The project's own `[environment.threads.functions]`.
    Project,
}

impl Family {
    /// Whether this family's thread-specific storage has keys a creating
    /// call hands out (C11 `tss_create`, POSIX `pthread_key_create`), which
    /// may carry a destructor. A family without one stores into fixed slots
    /// (FreeRTOS), so no destructor can ever clean a slot up.
    pub fn creates_storage_keys(self) -> bool {
        match self {
            Self::C11 | Self::Posix => true,
            Self::Profile(Profile::Freertos) => false,
            Self::Project => declared()
                .functions
                .values()
                .any(|op| op.op == ThreadOpKind::TssCreate),
        }
    }
}

impl Family {
    /// The name of this family's first function of `kind`: what a message
    /// shows when it suggests the call (`tss_get` for C11,
    /// `pthread_getspecific` for POSIX).
    pub fn function_of(self, kind: ThreadOpKind) -> Option<String> {
        let first = |table: &[(&str, ThreadOp)]| {
            table
                .iter()
                .find(|(_, op)| op.op == kind)
                .map(|(n, _)| (*n).to_string())
        };
        match self {
            Self::C11 => first(C11_OPS),
            Self::Posix => first(POSIX_OPS),
            Self::Profile(Profile::Freertos) => first(FREERTOS_OPS),
            Self::Project => declared()
                .functions
                .iter()
                .find(|(_, op)| op.op == kind)
                .map(|(n, _)| n.clone()),
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::C11 => "C11",
            Self::Posix => "POSIX",
            Self::Profile(Profile::Freertos) => "FreeRTOS",
            Self::Project => "declared",
        })
    }
}

fn lookup<T: Copy>(table: &[(&str, T)], name: &str) -> Option<T> {
    table.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

/// The built-in family (`"C11"` or `"POSIX"`) whose table holds the function
/// `name`, whether or not POSIX is read: what a declaration may not
/// redefine.
pub fn builtin_family_of(name: &str) -> Option<&'static str> {
    if lookup(C11_OPS, name).is_some() {
        Some("C11")
    } else if lookup(POSIX_OPS, name).is_some() {
        Some("POSIX")
    } else {
        None
    }
}

/// [`builtin_family_of`] for a type name.
pub fn builtin_type_family_of(name: &str) -> Option<&'static str> {
    if lookup(C11_TYPES, name).is_some() {
        Some("C11")
    } else if lookup(POSIX_TYPES, name).is_some() {
        Some("POSIX")
    } else {
        None
    }
}

/// The contract a shipped profile gives the function `name`.
pub fn profile_op(profile: Profile, name: &str) -> Option<ThreadOp> {
    match profile {
        Profile::Freertos => lookup(FREERTOS_OPS, name),
    }
}

fn profile_type(profile: Profile, name: &str) -> Option<ThreadTypeKind> {
    match profile {
        Profile::Freertos => lookup(FREERTOS_TYPES, name),
    }
}

/// The contract in force for the function `name`, and its family: C11, then
/// POSIX when read, then the selected profiles, then the project's own.
pub fn op_named(name: &str) -> Option<(Family, ThreadOp)> {
    let declarations = declared();
    if let Some(op) = lookup(C11_OPS, name) {
        return Some((Family::C11, op));
    }
    if declarations.posix {
        if let Some(op) = lookup(POSIX_OPS, name) {
            return Some((Family::Posix, op));
        }
    }
    for profile in &declarations.families {
        if let Some(op) = profile_op(*profile, name) {
            return Some((Family::Profile(*profile), op));
        }
    }
    declarations
        .functions
        .get(name)
        .map(|op| (Family::Project, *op))
}

/// What the type named `name` (after typedefs, if the caller resolved them)
/// holds, by the same families as [`op_named`].
pub fn type_kind(name: &str) -> Option<ThreadTypeKind> {
    let declarations = declared();
    lookup(C11_TYPES, name)
        .or_else(|| {
            declarations
                .posix
                .then(|| lookup(POSIX_TYPES, name))
                .flatten()
        })
        .or_else(|| {
            declarations
                .families
                .iter()
                .find_map(|p| profile_type(*p, name))
        })
        .or_else(|| declarations.types.get(name).copied())
}

/// One call that performs a thread-API operation.
#[derive(Debug, Clone)]
pub struct ThreadCall<'a> {
    /// The callee's name as written.
    pub name: String,
    /// The family whose contract the call follows.
    pub family: Family,
    /// The contract.
    pub op: ThreadOp,
    /// The call's arguments, in order.
    pub args: Vec<Node<'a>>,
}

impl<'a> ThreadCall<'a> {
    /// What the call does.
    pub fn kind(&self) -> ThreadOpKind {
        self.op.op
    }

    /// The argument the contract places `role` at, if it places it and the
    /// call has that many arguments.
    pub fn operand(&self, role: Role) -> Option<Node<'a>> {
        let position = self.op.position(role)?;
        self.args.get(position - 1).copied()
    }
}

/// The thread-API operation `call` (a `call_expression`) performs, or `None`
/// when its callee is not a plain name, does not resolve to a function, or
/// matches no contract in force.
pub fn thread_op<'a>(call: &Node<'a>, source: &str) -> Option<ThreadCall<'a>> {
    if call.kind() != "call_expression" {
        return None;
    }
    let callee = call.child_by_field_name("function")?;
    if callee.kind() != "identifier" {
        return None;
    }
    let name = get_node_text(&callee, source);
    let (family, op) = op_named(name)?;
    if !names_a_function(&callee, name, source) {
        return None;
    }
    let args: Vec<Node<'a>> = call
        .child_by_field_name("arguments")
        .map(|list| {
            list.child_nodes()
                .filter(|n| n.is_named() && n.kind() != "comment")
                .collect()
        })
        .unwrap_or_default();
    if op.arity.is_some_and(|arity| arity != args.len()) {
        return None;
    }
    Some(ThreadCall {
        name: name.to_string(),
        family,
        op,
        args,
    })
}

/// [`thread_op`] for the call, when it performs `kind`.
pub fn thread_op_of_kind<'a>(
    call: &Node<'a>,
    source: &str,
    kind: ThreadOpKind,
) -> Option<ThreadCall<'a>> {
    thread_op(call, source).filter(|c| c.kind() == kind)
}

/// Whether the occurrence `callee` of `name` names a function rather than an
/// object of that name (a local, a parameter, or a file-scope function
/// pointer).
fn names_a_function(callee: &Node, name: &str, source: &str) -> bool {
    match resolve_identifier_binding(callee, name, source) {
        None => true,
        Some(IdentifierBinding::Local(_) | IdentifierBinding::Parameter(_)) => false,
        Some(IdentifierBinding::Global(decl)) => declares_function(&decl, name, source),
    }
}

/// Whether `decl` declares `name` as a function: a declarator that is
/// `name(...)` itself, as opposed to `(*name)(...)`.
fn declares_function(decl: &Node, name: &str, source: &str) -> bool {
    let mut stack = vec![*decl];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_declarator" {
            if let Some(inner) = node.child_by_field_name("declarator") {
                if inner.kind() == "identifier" && get_node_text(&inner, source) == name {
                    return true;
                }
            }
        }
        stack.extend(node.child_nodes());
    }
    false
}
