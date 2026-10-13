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
//! function of the same name.
//!
//! A C11 or POSIX name the project defines itself (a shim implementing
//! `pthread_cond_wait` over another API, say) is the project's function, not
//! the library's: the call reaches that body, whatever the standard reserves
//! the name for. It performs no operation unless the project declares one
//! for it under `[environment.threads.functions]`, which is in force for
//! exactly those calls. The definition counts in this file (any linkage) or,
//! through the prescan's function summaries, in any other scanned file with
//! external linkage; another file's `static` is not reachable from here. A
//! shipped
//! profile's names are not shadowed this way: a project that carries the
//! RTOS kernel's source defines them as the profile describes.

use crate::analyze::context::ScopedTable;
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::points_to::{lvalue_of, LValue};
use crate::settings::threads::{
    declared, Blocking, Profile, Role, ThreadDeclarations, ThreadOp, ThreadOpKind, ThreadTypeKind,
};
use crate::settings::AllocatorContract;
use crate::utility::cert_c::ast_utils::{
    get_node_text, resolve_identifier_binding, resolve_identifier_declarator, IdentifierBinding,
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
        "pthread_mutex_clocklock",
        ThreadOp {
            object: Some(1),
            blocking: Some(Blocking::Timeout),
            ..op(K::MutexLock, 3)
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
/// - FreeRTOS has no condition variable, and a task has no join or detach.
///   The V11.2.0 kernel's thread-local storage slots take no destructor:
///   `vTaskSetThreadLocalStoragePointerAndDelCallback` is a vendor port's
///   addition, not in this kernel, so a project on such a port declares it
///   (`tss_set` with `destructor`).
///
/// The kernel's heap (`portable.h`) is read with the profile too:
/// `pvPortMalloc` allocates as `malloc` does and `vPortFree` frees its
/// argument ([`profile_allocator`], [`profile_deallocator`]).
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

/// FreeRTOS's heap, `portable.h` (V11.2.0).
const FREERTOS_ALLOCATORS: &[(&str, AllocatorContract)] =
    &[("pvPortMalloc", AllocatorContract::Malloc)];
/// The argument (0-based) each FreeRTOS heap function frees.
const FREERTOS_DEALLOCATORS: &[(&str, usize)] = &[("vPortFree", 0)];

/// The allocator contract a selected profile's kernel gives `name`.
pub fn profile_allocator(name: &str) -> Option<AllocatorContract> {
    declared().families.iter().find_map(|p| match p {
        Profile::Freertos => lookup(FREERTOS_ALLOCATORS, name),
    })
}

/// The argument (0-based) a selected profile's kernel function `name` frees.
pub fn profile_deallocator(name: &str) -> Option<usize> {
    declared().families.iter().find_map(|p| match p {
        Profile::Freertos => lookup(FREERTOS_DEALLOCATORS, name),
    })
}

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

/// The contract in force for the function `name`, and its family.
///
/// A C11 or POSIX name is asked `defined_by_project` first: when the project
/// defines the name itself, the call reaches that body, and only the
/// project's own declaration for it is in force. Otherwise C11, then POSIX
/// when read; a declaration of such a name does not apply to the library's
/// function. Any other name follows the selected profiles, then the
/// project's own declarations.
pub fn op_named(
    name: &str,
    defined_by_project: impl FnOnce() -> bool,
) -> Option<(Family, ThreadOp)> {
    let declarations = declared();
    if builtin_family_of(name).is_some() {
        if defined_by_project() {
            return declarations
                .functions
                .get(name)
                .map(|op| (Family::Project, *op));
        }
        if let Some(op) = lookup(C11_OPS, name) {
            return Some((Family::C11, op));
        }
        return declarations
            .posix
            .then(|| lookup(POSIX_OPS, name))
            .flatten()
            .map(|op| (Family::Posix, op));
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

/// Every function `declarations` give a contract, by name, in the order
/// [`op_named`] reads the families: C11, POSIX when read, the selected
/// profiles, then the project's own declarations. A project declaration of a
/// C11 or POSIX name is left out: it is in force only for a call that
/// reaches the project's own definition, which a name alone does not show.
pub fn functions_in_force(declarations: &ThreadDeclarations) -> Vec<(String, Family, ThreadOp)> {
    let posix: &[(&str, ThreadOp)] = if declarations.posix { POSIX_OPS } else { &[] };
    let builtin = C11_OPS
        .iter()
        .map(|(n, op)| (*n, Family::C11, *op))
        .chain(posix.iter().map(|(n, op)| (*n, Family::Posix, *op)));
    let profiles = declarations.families.iter().flat_map(|profile| {
        let table = match profile {
            Profile::Freertos => FREERTOS_OPS,
        };
        table
            .iter()
            .map(move |(n, op)| (*n, Family::Profile(*profile), *op))
    });
    let project = declarations
        .functions
        .iter()
        .filter(|(n, _)| builtin_family_of(n).is_none())
        .map(|(n, op)| (n.as_str(), Family::Project, *op));
    builtin
        .chain(profiles)
        .chain(project)
        .map(|(n, family, op)| (n.to_string(), family, op))
        .collect()
}

/// [`functions_in_force`] of `kind`.
pub fn functions_of_kind(
    declarations: &ThreadDeclarations,
    kind: ThreadOpKind,
) -> Vec<(String, Family, ThreadOp)> {
    functions_in_force(declarations)
        .into_iter()
        .filter(|(_, _, op)| op.op == kind)
        .collect()
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

/// The project's function definitions across every scanned file: the
/// prescan's function summaries, as a rule's `set_project_context` receives
/// them, scoped to the file being checked.
pub type ProjectFunctions = ScopedTable<FunctionSummary>;

/// The thread-API operation `call` (a `call_expression`) performs, or `None`
/// when its callee is not a plain name, does not resolve to a function, or
/// matches no contract in force. `project` holds the definitions in other
/// files, for a C11 or POSIX name the project defines itself
/// ([`op_named`]); `None` reads this file's alone.
pub fn thread_op<'a>(
    call: &Node<'a>,
    source: &str,
    project: Option<&ProjectFunctions>,
) -> Option<ThreadCall<'a>> {
    if call.kind() != "call_expression" {
        return None;
    }
    let callee = call.child_by_field_name("function")?;
    if callee.kind() != "identifier" {
        return None;
    }
    let name = get_node_text(&callee, source);
    let (family, op) = op_named(name, || {
        file_defines(call, name, source) || project.is_some_and(|p| defined_elsewhere(p, name))
    })?;
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
    project: Option<&ProjectFunctions>,
    kind: ThreadOpKind,
) -> Option<ThreadCall<'a>> {
    thread_op(call, source, project).filter(|c| c.kind() == kind)
}

/// The library function `call` (a `call_expression`) calls: its callee's
/// name, when that is a plain name that resolves to a function (not an
/// object holding a pointer, ADR-0006) and neither this file nor another
/// scanned file defines a function of that name for this call to reach.
/// `None` when the project supplies the function itself. The same test the
/// thread-API contracts take, for a rule that asks what a standard function
/// does (blocks, for instance).
pub fn library_call<'a>(
    call: &Node,
    source: &'a str,
    project: Option<&ProjectFunctions>,
) -> Option<&'a str> {
    let callee = call.child_by_field_name("function")?;
    if callee.kind() != "identifier" {
        return None;
    }
    let name = get_node_text(&callee, source);
    let shadowed =
        file_defines(call, name, source) || project.is_some_and(|p| defined_elsewhere(p, name));
    (!shadowed && names_a_function(&callee, name, source)).then_some(name)
}

/// Whether another scanned file defines `name` with external linkage, so a
/// call from this file can reach it. Another file's `static` definition is
/// that file's alone: a call here still reaches the library (ADR-0006). This
/// file's own definitions are [`file_defines`]'.
fn defined_elsewhere(project: &ProjectFunctions, name: &str) -> bool {
    project
        .get(name)
        .is_some_and(|summary| !summary.has_internal_linkage)
}

/// Whether the file holding `node` defines the function `name` itself: a
/// definition by that name, with any linkage, or a `static` declaration of
/// one (whose definition must follow in this file). A plain prototype still
/// declares the library's function. File-scope declarations only, through
/// preprocessor groups, never into a body.
fn file_defines(node: &Node, name: &str, source: &str) -> bool {
    let mut root = *node;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let mut stack = vec![root];
    while let Some(scope) = stack.pop() {
        for child in scope.child_nodes() {
            match child.kind() {
                "function_definition"
                    if child
                        .child_by_field_name("declarator")
                        .is_some_and(|d| declares_function(&d, name, source)) =>
                {
                    return true;
                }
                "declaration"
                    if declares_function(&child, name, source)
                        && child.child_nodes().any(|c| {
                            c.kind() == "storage_class_specifier"
                                && get_node_text(&c, source).trim() == "static"
                        }) =>
                {
                    return true;
                }
                kind if kind.starts_with("preproc_") => stack.push(child),
                _ => {}
            }
        }
    }
    false
}

/// The function `call` (a `call_expression`) calls, by name: its callee
/// when that is a plain identifier resolving to a function, not to a local,
/// a parameter or a file-scope function pointer (ADR-0006). `None` for a
/// call through a pointer or a member such as `ops->lock`. For a rule that
/// must still read a name no thread-API family describes.
pub fn called_function<'a>(call: &Node, source: &'a str) -> Option<&'a str> {
    let callee = call.child_by_field_name("function")?;
    if callee.kind() != "identifier" {
        return None;
    }
    let name = get_node_text(&callee, source);
    names_a_function(&callee, name, source).then_some(name)
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

impl<'a> ThreadCall<'a> {
    /// The function a thread-create call starts the thread in: its
    /// [`Role::Entry`] operand, through casts, parentheses and `&`, when that
    /// names a function (not a function pointer held in an object of that
    /// name, ADR-0006). `None` for a call of any other kind, or an entry
    /// this file cannot name.
    pub fn entry_function(&self, source: &str) -> Option<String> {
        let mut entry = strip_to_operand(self.operand(Role::Entry)?);
        // `(thrd_start_t)&work` parses as `(thrd_start_t) & work` when the
        // typedef is not visible to the parser: a bitwise AND, which a start
        // routine can never be. Read it as the cast it is.
        if entry.kind() == "binary_expression"
            && entry
                .child_by_field_name("operator")
                .is_some_and(|op| op.kind() == "&")
            && entry
                .child_by_field_name("left")
                .is_some_and(|l| l.kind() == "parenthesized_expression")
        {
            entry = strip_to_operand(entry.child_by_field_name("right")?);
        } else if entry.kind() == "pointer_expression" {
            entry = strip_to_operand(entry.child_by_field_name("argument")?);
        }
        if entry.kind() != "identifier" {
            return None;
        }
        let name = get_node_text(&entry, source);
        names_a_function(&entry, name, source).then(|| name.to_string())
    }
}

/// Whether `operand` is a call that yields the calling thread's own handle
/// (C11 `thrd_current()`, POSIX `pthread_self()`, a declared family's), so
/// a join or detach of it acts on the thread that makes it.
pub fn is_own_thread(operand: &Node, source: &str, project: Option<&ProjectFunctions>) -> bool {
    let operand = strip_to_operand(*operand);
    thread_op_of_kind(&operand, source, project, ThreadOpKind::ThreadSelf).is_some()
}

/// `node` without the casts and parentheses around it.
fn strip_to_operand(node: Node) -> Node {
    match node.kind() {
        "cast_expression" => node
            .child_by_field_name("value")
            .map_or(node, strip_to_operand),
        "parenthesized_expression" => node
            .child_nodes()
            .find(|c| c.is_named() && c.kind() != "comment")
            .map_or(node, strip_to_operand),
        _ => node,
    }
}

/// Which synchronization object an operand names: a mutex, condition
/// variable, thread handle or key, identified by the declaration its name
/// resolves to and the member path below it (ADR-0006). `&m`, `m`, `(m)` and
/// `(&m)` are one object; `p->m` and `q->m` are two, and so are a global `m`
/// and a local `m` that shadows it.
///
/// An array element is keyed by its index too: `&locks[i]` twice is one
/// object, while `&locks[i]` and `&locks[j]`, or `&locks[1]`, are different
/// elements as far as the code shows. An index is keyed by its spelling
/// (see [`index_key`]). [`SyncObject::array`] drops the indices,
/// for a question about the whole array (were the handles stored into
/// `thr[i]` all joined, through `thr[j]` in another loop?).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SyncObject {
    /// Where the root name is declared: the declarator's start byte, or the
    /// name itself when no declaration in this file binds it.
    root: SyncRoot,
    /// The member path from the root, spelling-independent.
    path: LValue,
    /// The subscripts along the path, outermost last.
    indices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SyncRoot {
    Declared(usize),
    Undeclared(String),
}

impl SyncObject {
    /// The same object with its subscripts dropped: the whole array an
    /// element belongs to.
    pub fn array(&self) -> SyncObject {
        SyncObject {
            indices: Vec::new(),
            ..self.clone()
        }
    }

    /// Whether this object is `outer` or lies inside it: a member at any
    /// depth, or any element when `outer` is spelled with other subscripts
    /// or none. A call handed `&s` is handed `s.lock` too.
    pub fn within(&self, outer: &SyncObject) -> bool {
        self.root == outer.root && (self.path == outer.path || self.path.is_inside(&outer.path))
    }
}

/// The object `operand` names, or `None` when it names none this file can
/// pin down: a call's result, a literal, an arithmetic expression.
pub fn sync_object(operand: &Node, source: &str) -> Option<SyncObject> {
    let path = lvalue_of(operand, source)?;
    let mut indices = Vec::new();
    let root = root_identifier(*operand, &mut indices)?;
    let name = get_node_text(&root, source);
    let indices = indices
        .iter()
        .rev()
        .map(|index| index_key(*index, source))
        .collect();
    Some(SyncObject {
        root: declared_at(&root, name, source),
        path,
        indices,
    })
}

fn declared_at(ident: &Node, name: &str, source: &str) -> SyncRoot {
    match resolve_identifier_declarator(ident, name, source) {
        Some((_, declarator)) => SyncRoot::Declared(declarator.start_byte()),
        None => SyncRoot::Undeclared(name.to_string()),
    }
}

/// An index is a value, not an object: two loops that each declare their
/// own `i` walk the same elements as far as the code shows, so a lock loop
/// and an unlock loop over `m[i]` pair up. The index is therefore keyed by
/// its spelling without whitespace (casts and parentheses dropped), never by
/// the declaration a counter resolves to.
fn index_key(index: Node, source: &str) -> String {
    get_node_text(&strip_to_operand(index), source)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// The identifier an lvalue chain bottoms out at, along the same unwraps
/// [`lvalue_of`] takes, collecting each subscript's index on the way in.
fn root_identifier<'a>(node: Node<'a>, indices: &mut Vec<Node<'a>>) -> Option<Node<'a>> {
    match node.kind() {
        "identifier" => Some(node),
        "subscript_expression" => {
            if let Some(index) = node.child_by_field_name("index") {
                indices.push(index);
            }
            root_identifier(node.child_by_field_name("argument")?, indices)
        }
        "field_expression" | "pointer_expression" => {
            root_identifier(node.child_by_field_name("argument")?, indices)
        }
        "cast_expression" => root_identifier(node.child_by_field_name("value")?, indices),
        "parenthesized_expression" => node
            .child_nodes()
            .find(|c| c.is_named() && c.kind() != "comment")
            .and_then(|c| root_identifier(c, indices)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lang_parsing_substrate::query;

    fn objects(source: &str) -> Vec<Option<SyncObject>> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        query::find_descendants_of_kind(tree.root_node(), "call_expression")
            .iter()
            .filter(|c| {
                c.child_by_field_name("function")
                    .is_some_and(|f| get_node_text(&f, source) == "use")
            })
            .map(|c| {
                let arg = c
                    .child_by_field_name("arguments")
                    .and_then(|a| a.named_child(0))
                    .unwrap();
                sync_object(&arg, source)
            })
            .collect()
    }

    #[test]
    fn one_object_however_it_is_spelled() {
        let o = objects(
            "int m; struct s { int a; } *p, *q;\n\
             void f(void) { use(&m); use(m); use((&(m))); use(&p->a); use(&q->a); use(&(*p).a); }",
        );
        assert_eq!(o[0], o[1]);
        assert_eq!(o[0], o[2]);
        assert_ne!(o[3], o[4]);
        assert_eq!(o[3], o[5]);
    }

    #[test]
    fn an_element_is_keyed_by_its_index() {
        let o = objects(
            "int m[4];\n\
             void f(int i, int j) { use(&m[i]); use(&(m[ i ])); use(&m[j]); use(&m[1]); use(&m[ 1 ]); \
               for (int k = 0; k < 4; k++) use(&m[k]); for (int k = 0; k < 4; k++) use(&m[k]); }",
        );
        assert_eq!(o[5], o[6]);
        assert_eq!(o[0], o[1]);
        assert_ne!(o[0], o[2]);
        assert_ne!(o[0], o[3]);
        assert_eq!(o[3], o[4]);
        let whole: Vec<_> = o.iter().map(|x| x.as_ref().unwrap().array()).collect();
        assert!(whole.iter().all(|w| *w == whole[0]));
    }

    #[test]
    fn a_shadowing_local_is_another_object() {
        let o = objects("int m;\nvoid f(void) { use(&m); { int m; use(&m); } }");
        assert_ne!(o[0], o[1]);
    }

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        parser.parse(source, None).unwrap()
    }

    #[test]
    fn a_thread_starts_in_the_function_its_entry_names() {
        let source = "#include <threads.h>\nint work(void *a);\n\
                      void f(thrd_t *t) { thrd_create(t, (thrd_start_t)&work, 0); }\n\
                      void g(thrd_t *t, thrd_start_t work) { thrd_create(t, work, 0); }";
        let tree = parse(source);
        let calls = query::find_descendants_of_kind(tree.root_node(), "call_expression");
        let entries: Vec<_> = calls
            .iter()
            .filter_map(|c| thread_op(c, source, None))
            .map(|c| c.entry_function(source))
            .collect();
        assert_eq!(entries, vec![Some("work".to_string()), None]);
    }

    #[test]
    fn the_own_handle_comes_from_a_thread_self_call() {
        let source = "#include <pthread.h>\n\
                      void f(pthread_t t) { pthread_detach((pthread_self())); pthread_detach(t); }";
        let tree = parse(source);
        let detaches: Vec<_> = query::find_descendants_of_kind(tree.root_node(), "call_expression")
            .into_iter()
            .filter_map(|c| thread_op(&c, source, None))
            .filter(|c| c.kind() == ThreadOpKind::ThreadDetach)
            .map(|c| is_own_thread(&c.operand(Role::Handle).unwrap(), source, None))
            .collect();
        assert_eq!(detaches, vec![true, false]);
    }

    #[test]
    fn a_call_result_names_no_object() {
        let o = objects("int *get(void);\nvoid f(void) { use(get()); }");
        assert_eq!(o[0], None);
    }
}
