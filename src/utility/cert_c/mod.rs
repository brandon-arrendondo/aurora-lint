// Utility modules for CERT C rules
/// Reusable functions for navigating and extracting information from the C AST.
pub mod ast_utils;
/// Which automatic object an expression addresses, and the automatic object a
/// local pointer's value addresses (DCL30-C, TS 17961 addrescape).
pub mod automatic_storage;
/// Calls that can block made while a mutex is held on every path to them
/// (the analysis CON05-C and POS52-C share).
pub mod blocking_under_lock;
/// Shared call-role classification (allocator/printf-family/scanf-family/etc.)
/// on top of `std_functions` -- single source of truth so rules stop
/// independently reinventing (and disagreeing on) these name lists.
pub mod call_roles;
/// How far a memory-clearing call's write reaches, so a rule can tell
/// whether a pointer stored inside the destination survived it.
pub mod clearing_extent;
/// Declared credential sinks (the library arguments that receive a secret)
/// and the page-locking calls, so a rule asks whether a buffer is sensitive
/// by what it reaches rather than by its name.
pub mod credential_sinks;
/// The integer data model a scan credits: ISO C's guaranteed minimums unless
/// a project declares ILP32, LP64 or LLP64.
pub mod data_model;
/// Reusable functions for analyzing C declarators (arrays, pointers, function pointers).
pub mod declarator_utils;
/// The C type of an expression, read from the declarations it names and
/// the typedef chain -- never from a name map or a substring of type text.
pub mod expr_type;
pub mod float_typing;
/// Which functions a file-scope function-pointer variable is bound to
/// across one translation unit -- initializer AND later assignment, every
/// binding rather than the last, so a rule can ask what a call through the
/// pointer may reach.
pub mod fn_ptr_bindings;
/// Which vararg slot each conversion specification of a format string
/// consumes, and whether that conversion dereferences the pointer it gets --
/// so a check on a `...` argument stops treating every tail slot alike.
pub mod format_slots;
/// Structural "is this variable guarded here?" queries -- the AST relation
/// that per-rule text searches for a canonical guard spelling stand in for.
pub mod guard_dominance;
/// The last plain write to an lvalue before a point in a function, by
/// spelling: which value of a variable a site sees.
pub mod last_write;
/// Whether an ISO C or POSIX library call has a side effect (C11 5.1.2.3p2, errno
/// included): the table behind the `stdlib_call_effects` contract.
pub mod library_effects;
/// The "consume a length in a loop" idiom (`while (len) { len -= n; }`),
/// recognized structurally so an overflow rule stops reading a loop-bounded
/// subtraction as an unguarded one.
pub mod loop_consumption;
/// When a mutex is destroyed while it may still be in use: held by the
/// destroying function, used after the destroy, or locked by a thread that
/// may still run (the analysis CON31-C and POS48-C share).
pub mod mutex_lifetime;
/// A node's children in order at linear cost: indexed when there are few,
/// a cursor when there are many (`child(i)` walks from the first child).
pub mod node_children;
/// The conditions whose truth value is known where a site executes, with
/// stale ones dropped: the shared reading of a guard for the rules that need
/// a value proven non-zero there (INT33-C's divisor, MEM04-C's size).
pub mod nonzero_facts;
/// Shared helpers for arithmetic-overflow-detection rules (INT30-C, INT32-C).
pub mod overflow_helpers;
/// Positive pointer-type inference, so the integer-hazard rules (INT00-C,
/// INT30-C, INT31-C, INT32-C) stop reading pointer arithmetic as integer
/// arithmetic.
pub mod pointer_typing;
/// Preprocessing tokens of a `#define` replacement list, literals and
/// comments told apart from code, with `#`/`##`-operand and
/// unevaluated-operand marks.
pub mod pp_tokens;
/// Win32 registry calls that take a root key, and whether a call asks for
/// write access, so a least-privilege rule tells an HKLM write from a read.
pub mod registry_access;
/// Whether a stored function result is tested against the value that
/// signals the function's failure, by resolved identity and in a test
/// context -- the question ERR33-C asks of every assigned result.
pub mod result_checks;
/// Which functions a translation unit registers with `signal`, `sigaction`,
/// `atexit` or `at_quick_exit`, by what the registration is given
/// (identity by declaration) rather than by what a function is named.
pub mod signal_handlers;
pub mod size_analysis;
/// Lookup of known C standard library / POSIX / Windows socket function names.
pub mod std_functions;
/// Slicing and truncating source text on character boundaries, so a
/// multibyte character at the cut cannot panic the scan.
pub mod text_bounds;
/// Which thread-API operation a call performs (create, lock, wait, store
/// thread-specific data, ...), across C11, POSIX and declared families.
pub mod thread_api;
pub mod thread_storage;
pub mod variable_analysis;
