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
pub mod size_analysis;
/// Lookup of known C standard library / POSIX / Windows socket function names.
pub mod std_functions;
pub mod variable_analysis;
