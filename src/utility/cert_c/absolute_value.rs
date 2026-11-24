//! The library's absolute-value functions, `abs`, `labs` and `llabs` (C11
//! 7.22.6.1): which calls in a file are calls of them, and what a value's
//! type says about the argument a call of one receives.
//!
//! A call is the library's only when nothing in the project takes the name
//! over: a definition, a `static` declaration, a `#define`, or an object
//! (a function pointer among them) the call resolves to where it stands
//! (ADR-0006). The parameter type is the library's, so the argument
//! converts to it at the call whatever it was cast to (C11 6.5.2.2p7), and
//! the absolute value of that type's most negative value is undefined.

use crate::analyze::context::ProjectContext;
use crate::analyze::noreturn::library_names_redefined_among;
use crate::utility::cert_c::ast_utils::{
    get_node_text, resolve_identifier_declarator, DefinedMacroNames,
};
use crate::utility::cert_c::data_model::{IntFacts, IntWidth, Rank};
use crate::utility::cert_c::declarator_utils::declares_function;
use crate::utility::cert_c::expr_type::{CType, Sign};
use std::collections::HashSet;
use std::sync::Arc;
use tree_sitter::Node;

/// The library's absolute-value functions and the rank of each one's
/// parameter type: `int`, `long` and `long long`.
pub const FUNCTIONS: [(&str, Rank); 3] = [
    ("abs", Rank::Int),
    ("labs", Rank::Long),
    ("llabs", Rank::LongLong),
];

/// The rank of the parameter type of the library's absolute-value
/// function `name`, when `name` is one of [`FUNCTIONS`].
pub fn parameter_rank(name: &str) -> Option<Rank> {
    FUNCTIONS
        .iter()
        .find(|(function, _)| *function == name)
        .map(|(_, rank)| *rank)
}

/// Which of `candidates`, library function names, still name the library's
/// function in the file `root`: none the project defines
/// (`defined_by_project`, its function summaries), none this file defines
/// or declares `static`, and none a `#define` makes a macro, in this file
/// or in any file or header the project scanned, in any `#if` branch
/// (`project`, [`ProjectMacroNames`]). Built once per file; a call must
/// still resolve to no object where it stands
/// ([`sole_argument_of_function_call`]).
pub fn library_names(
    root: &Node,
    source: &str,
    candidates: &[&'static str],
    defined_by_project: impl Fn(&str) -> bool,
    project: &ProjectMacroNames,
) -> Vec<&'static str> {
    let redefined = library_names_redefined_among(root, source, |name| candidates.contains(&name));
    let own_macros = DefinedMacroNames::of(source);
    candidates
        .iter()
        .copied()
        .filter(|name| {
            !defined_by_project(name)
                && !redefined.contains(*name)
                && !own_macros.contains(name)
                && !project.contains(name)
        })
        .collect()
}

/// Every name a `#define` in a scanned file or header makes a macro, in
/// any `#if` branch: the project's function-like and object-like macro
/// names. Kept by a rule from its project context; empty without one.
#[derive(Clone, Debug, Default)]
pub struct ProjectMacroNames {
    function_like: Arc<HashSet<String>>,
    object_like: Arc<HashSet<String>>,
}

impl ProjectMacroNames {
    /// The names `context` holds.
    pub fn of(context: &ProjectContext) -> Self {
        Self {
            function_like: context.function_macro_names.clone(),
            object_like: context.defined_macro_names.clone(),
        }
    }

    /// Whether some scanned file or header defines `name` as a macro.
    pub fn contains(&self, name: &str) -> bool {
        self.function_like.contains(name) || self.object_like.contains(name)
    }
}

/// The one argument of `call`, whose callee `callee` resolves where it
/// stands to a function or to nothing the file declares, never to an
/// object of that name, a pointer to a function included (ADR-0006). A
/// comment in the argument list is not an argument.
pub fn sole_argument_of_function_call<'t>(
    call: &Node<'t>,
    callee: &Node<'t>,
    source: &str,
) -> Option<Node<'t>> {
    let bound_to_object =
        resolve_identifier_declarator(callee, get_node_text(callee, source), source)
            .is_some_and(|(_, declarator)| !declares_function(&declarator));
    if bound_to_object {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let mut args = arguments
        .named_children(&mut cursor)
        .filter(|n| n.kind() != "comment");
    match (args.next(), args.next()) {
        (Some(arg), None) => Some(arg),
        _ => None,
    }
}

/// `arg` through its parentheses and casts: the operand they enclose, and
/// the casts outermost first, so the operand converts through them in
/// reverse order.
pub fn peel_casts<'t>(mut arg: Node<'t>) -> Option<(Node<'t>, Vec<Node<'t>>)> {
    let mut casts = Vec::new();
    loop {
        match arg.kind() {
            "parenthesized_expression" => arg = arg.named_child(0)?,
            "cast_expression" => {
                casts.push(arg);
                arg = arg.child_by_field_name("value")?;
            }
            _ => return Some((arg, casts)),
        }
    }
}

/// What the values of an integer type are known to be: its signedness
/// (`None` for plain `char`, which may be either) and the widths the data
/// model allows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntegerValues {
    /// `Some(true)` for a signed type, `Some(false)` for an unsigned one.
    pub signed: Option<bool>,
    /// Its widths under the data model.
    pub width: IntWidth,
}

impl IntegerValues {
    /// The values of the integer type `ty` under `facts`; `None` for an
    /// enumeration (whose compatible type is the implementation's), a type
    /// that is not an integer type, or one not known.
    pub fn of(ty: &CType, facts: IntFacts) -> Option<Self> {
        let signed = |sign: &Sign| match sign {
            Sign::Signed => Some(true),
            Sign::Unsigned => Some(false),
            Sign::PlainChar => None,
        };
        match ty {
            CType::Int { sign, rank } => Some(Self {
                signed: signed(sign),
                width: facts.width_of(*rank),
            }),
            CType::IntOfWidth {
                sign,
                min_bits,
                max_bits,
            } => Some(Self {
                signed: signed(sign),
                width: IntWidth {
                    rank: None,
                    min: *min_bits,
                    max: *max_bits,
                },
            }),
            _ => None,
        }
    }

    /// The signed integer type of rank `rank` under `facts`.
    pub fn signed_of_rank(rank: Rank, facts: IntFacts) -> Self {
        Self {
            signed: Some(true),
            width: facts.width_of(rank),
        }
    }

    /// Whether every one of these values is a value of `to` on every
    /// implementation the data model allows, so converting it to `to`
    /// keeps it (C11 6.3.1.3p1): the widest these may be is no wider than
    /// the narrowest `to` may be, and one bit narrower when only `to` has a
    /// sign bit. Plain `char` fits only as an unsigned type would.
    pub fn fit_in(self, to: Self) -> bool {
        let Some(bits) = self.width.max else {
            return false;
        };
        match (self.signed, to.signed) {
            (Some(true), Some(true)) | (Some(false), Some(false)) => bits <= to.width.min,
            (Some(false) | None, Some(true)) => bits < to.width.min,
            _ => false,
        }
    }

    /// Whether none of these values is the most negative value of the
    /// signed type `parameter`, on every implementation the data model
    /// allows: the widest these may be is below the narrowest `parameter`
    /// may be, so even a signed one stops above its minimum.
    pub fn exclude_minimum_of(self, parameter: Self) -> bool {
        self.width
            .max
            .is_some_and(|bits| bits < parameter.width.min)
    }
}
