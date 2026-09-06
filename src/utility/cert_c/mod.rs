// Utility modules for CERT C rules
/// Reusable functions for navigating and extracting information from the C AST.
pub mod ast_utils;
/// Shared call-role classification (allocator/printf-family/scanf-family/etc.)
/// on top of `std_functions` -- single source of truth so rules stop
/// independently reinventing (and disagreeing on) these name lists.
pub mod call_roles;
/// Reusable functions for analyzing C declarators (arrays, pointers, function pointers).
pub mod declarator_utils;
pub mod float_typing;
/// Structural "is this variable guarded here?" queries -- the AST relation
/// that per-rule text searches for a canonical guard spelling stand in for.
pub mod guard_dominance;
/// Shared helpers for arithmetic-overflow-detection rules (INT30-C, INT32-C).
pub mod overflow_helpers;
/// Positive pointer-type inference, so the integer-hazard rules (INT00-C,
/// INT30-C, INT31-C, INT32-C) stop reading pointer arithmetic as integer
/// arithmetic.
pub mod pointer_typing;
pub mod size_analysis;
/// Lookup of known C standard library / POSIX / Windows socket function names.
pub mod std_functions;
pub mod variable_analysis;
