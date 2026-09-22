//! What a memory-clearing call overwrites, expressed in the field paths a
//! rule tracks.
//!
//! `call_roles::is_memory_clearing_call` and `FunctionSummary::clears_params`
//! answer *whether* a call clears a destination. This module answers *how
//! far the write reaches*, which is what a rule needs before it may conclude
//! that a pointer stored inside that destination survived the call.

use crate::analyze::points_to::{lvalue_of, LValue};
use crate::utility::cert_c::ast_utils::{get_node_text, is_dereference_expression};
use tree_sitter::Node;

/// The storage a clearing call writes over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearedExtent {
    /// The destination object and everything inside it, and nothing beyond
    /// it: `memset(&sOut, 0, sizeof(sOut))`.
    Object(LValue),
    /// The destination member *and the rest of the object it sits in* --
    /// the "zero from this member to the end of the struct" idiom, whose
    /// length is measured against the enclosing object rather than the
    /// destination. sqlite's fts3_aux.c: `memset(&pCsr->csr, 0,
    /// ((u8*)&pCsr[1]) - (u8*)&pCsr->csr)`. Named by the root variable,
    /// because the tail is everything reachable under it.
    ObjectTail(String),
}

impl ClearedExtent {
    /// True when `lv` names storage this call overwrites.
    ///
    /// Only a field path ever qualifies. A bare variable is the pointer
    /// itself, which lives *outside* the memory being written: `memset(p,
    /// 0, n)` does not rebind `p`, and the rebinding a `&p` argument does
    /// imply belongs to the caller's address-of handling, not here.
    pub fn covers(&self, lv: &LValue) -> bool {
        match self {
            ClearedExtent::Object(dest) => lv.is_inside(dest),
            ClearedExtent::ObjectTail(root) => lv.is_field() && lv.root_var() == root,
        }
    }
}

/// The extent of a clearing call, from its destination argument and the
/// arguments that follow it.
///
/// The remaining arguments are searched rather than indexed because the
/// length sits in a different position in every signature this feeds
/// (`memset(s, c, n)`, `bzero(s, n)`, `memset_s(s, smax, c, n)`), and a
/// project wrapper or macro has no fixed signature at all.
///
/// The extent is NOT gated on the length proving the destination is covered
/// in full. A partial clear (`memset(&s, 0, 4)`) still makes the pointers it
/// spans unreadable to us, and a rule that reports a *use of freed memory*
/// must be able to say the value read is the one that was freed. An
/// unmodellable write over the object it lives in is exactly the evidence
/// that it is not.
pub fn cleared_extent(dest: &Node, rest: &[Node], source: &str) -> Option<ClearedExtent> {
    let dest_lv = lvalue_of(dest, source)?;
    let root = dest_lv.root_var();
    if rest
        .iter()
        .any(|arg| spans_to_object_end(arg, root, source))
    {
        return Some(ClearedExtent::ObjectTail(root.to_string()));
    }
    Some(ClearedExtent::Object(dest_lv))
}

/// The distance between two addresses taken inside `root` --
/// `((u8*)&pCsr[1]) - (u8*)&pCsr->csr` -- the span from a member to one
/// past the end of the object.
///
/// Both operands must be addresses *taken* (`&x`), not values read out of
/// the object. That is what separates this idiom from an ordinary length
/// that happens to be computed from the same struct: `memset(&p->buf, 0,
/// p->end - p->start)` says nothing about how far past `buf` the write
/// reaches, and must not widen the extent to the whole of `p`.
fn spans_to_object_end(len: &Node, root: &str, source: &str) -> bool {
    let len = unwrap_expr(len);
    if len.kind() != "binary_expression" {
        return false;
    }
    let Some(op) = len.child_by_field_name("operator") else {
        return false;
    };
    if get_node_text(&op, source) != "-" {
        return false;
    }
    let (Some(left), Some(right)) = (
        len.child_by_field_name("left"),
        len.child_by_field_name("right"),
    ) else {
        return false;
    };
    [left, right].iter().all(|side| {
        let side = unwrap_expr(side);
        side.kind() == "pointer_expression"
            && !is_dereference_expression(&side, source)
            && lvalue_of(&side, source).is_some_and(|lv| lv.root_var() == root)
    })
}

/// Peel parentheses and casts, which carry no storage identity of their own.
fn unwrap_expr<'a>(node: &Node<'a>) -> Node<'a> {
    let mut cur = *node;
    loop {
        let next = match cur.kind() {
            "parenthesized_expression" => (0..cur.child_count())
                .filter_map(|i| cur.child(i))
                .find(|c| c.kind() != "(" && c.kind() != ")"),
            "cast_expression" => cur.child_by_field_name("value"),
            _ => None,
        };
        match next {
            Some(inner) => cur = inner,
            None => return cur,
        }
    }
}
