// Utility modules for CERT C rules
/// Reusable functions for navigating and extracting information from the C AST.
pub mod ast_utils;
/// Shared call-role classification (allocator/printf-family/scanf-family/etc.)
/// on top of `std_functions` -- single source of truth so rules stop
/// independently reinventing (and disagreeing on) these name lists.
pub mod call_roles;
/// How far a memory-clearing call's write reaches, so a rule can tell
/// whether a pointer stored inside the destination survived it.
pub mod clearing_extent;
/// Reusable functions for analyzing C declarators (arrays, pointers, function pointers).
pub mod declarator_utils;
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
/// The "consume a length in a loop" idiom (`while (len) { len -= n; }`),
/// recognized structurally so an overflow rule stops reading a loop-bounded
/// subtraction as an unguarded one.
pub mod loop_consumption;
/// Shared helpers for arithmetic-overflow-detection rules (INT30-C, INT32-C).
pub mod overflow_helpers;
/// Positive pointer-type inference, so the integer-hazard rules (INT00-C,
/// INT30-C, INT31-C, INT32-C) stop reading pointer arithmetic as integer
/// arithmetic.
pub mod pointer_typing;
/// Which functions a translation unit registers with `signal`, `sigaction`,
/// `atexit` or `at_quick_exit`, by what the registration is given
/// (identity by declaration) rather than by what a function is named.
pub mod signal_handlers;
pub mod size_analysis;
/// Lookup of known C standard library / POSIX / Windows socket function names.
pub mod std_functions;
pub mod variable_analysis;
