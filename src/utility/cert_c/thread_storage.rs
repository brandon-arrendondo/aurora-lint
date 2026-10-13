// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! Which storage a thread-create call hands its new thread: the one analysis
//! CON34-C and POS50-C share (the C11/POSIX twins read one hazard, keyed by
//! the API only in which family each reports).
//!
//! Another thread accessing an object of automatic or thread storage duration
//! is implementation-defined (C 6.2.4), and CERT reports it however the
//! object's lifetime relates to the thread's: a join before the object goes
//! out of scope earns no credit. So the question asked here is only what the
//! argument names, never what happens to the thread afterwards.
//!
//! Identity is by declaration (ADR-0006): the argument's root name is
//! resolved to the declaration that binds it, and its storage class is read
//! there. The argument names an object when it is:
//!
//! - `&x`, `&x.member`, `&x[i]` (through casts and parentheses) where `x`
//!   is a declared object, or an array `x` itself, which decays to a pointer
//!   to its first element;
//! - not reached through a pointer: `&p->member`, `&(*p).member` and `&p[i]`
//!   for a pointer `p` name the pointee, whose storage this file cannot see.
//!
//! A thread handle (`thrd_t`, `pthread_t`, a declared family's) is not
//! reported: passing `&child_tid` to the thread that creates the child is how
//! one thread hands back another's handle, and CERT's own compliant
//! thread-specific-storage example does exactly that.
//!
//! Thread storage is `_Thread_local`, `thread_local`, `__thread` or
//! `__declspec(thread)`. The parser respells `_Thread_local` as
//! `thread_local`, which the grammar reads as a storage class.

use crate::settings::threads::{Role, ThreadTypeKind};
use crate::utility::cert_c::ast_utils::{
    declaration_has_storage_class, declaration_is_thread_local, get_node_text,
    is_dereference_expression, resolve_identifier_binding, resolve_identifier_declarator,
    IdentifierBinding,
};
use crate::utility::cert_c::thread_api::{self, ThreadCall};
use tree_sitter::Node;

/// The storage duration of an object handed to a new thread, when it is one
/// the new thread must not be given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedStorage {
    /// A block-scope object without `static` or `extern`, or a parameter.
    Automatic,
    /// A `_Thread_local`, `thread_local` or `__thread` object: each thread
    /// has its own, and the new thread is handed its creator's.
    ThreadLocal,
}

/// An object of automatic or thread storage duration a thread creation
/// passes to its new thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassedObject {
    /// The object's name as declared.
    pub name: String,
    /// Its storage duration.
    pub storage: SharedStorage,
}

/// The automatic or thread-local object `create` (a thread-create call)
/// passes as its new thread's argument, or `None` when the argument names no
/// such object: static or allocated storage, a pointer's pointee, a value,
/// or no argument at all.
pub fn passed_object(create: &ThreadCall, source: &str) -> Option<PassedObject> {
    let arg = strip(create.operand(Role::Arg)?);
    let (root, addressed, whole) =
        if arg.kind() == "pointer_expression" && !is_dereference_expression(&arg, source) {
            let lvalue = strip(arg.child_by_field_name("argument")?);
            let whole = lvalue.kind() != "field_expression";
            (object_root(lvalue, source)?, true, whole)
        } else if arg.kind() == "identifier" {
            (arg, false, true)
        } else {
            return None;
        };
    let name = get_node_text(&root, source);
    let (decl, declarator) = resolve_identifier_declarator(&root, name, source)?;
    // A thread handle handed to the thread that fills it in is how one thread
    // returns another's handle; CERT's own compliant thread-specific-storage
    // example passes `&child_tid` this way, so a handle is not reported.
    let is_handle = whole
        && decl.child_by_field_name("type").is_some_and(|ty| {
            thread_api::type_kind(get_node_text(&ty, source).trim()) == Some(ThreadTypeKind::Thread)
        });
    if is_handle {
        return None;
    }
    // A bare name passes a pointer to its object only when it is an array,
    // and an array parameter is a pointer.
    let is_array = declarator.kind() == "array_declarator";
    let binding = resolve_identifier_binding(&root, name, source)?;
    if !addressed && (!is_array || matches!(binding, IdentifierBinding::Parameter(_))) {
        return None;
    }
    let thread_local = decl.kind() == "declaration" && declaration_is_thread_local(&decl, source);
    let storage = if thread_local {
        SharedStorage::ThreadLocal
    } else {
        match binding {
            IdentifierBinding::Parameter(_) => SharedStorage::Automatic,
            IdentifierBinding::Local(_)
                if !declaration_has_storage_class(&decl, "static", source)
                    && !declaration_has_storage_class(&decl, "extern", source) =>
            {
                SharedStorage::Automatic
            }
            _ => return None,
        }
    };
    Some(PassedObject {
        name: name.to_string(),
        storage,
    })
}

/// The declared object whose own storage `lvalue` (the operand of `&`) lies
/// in: `x`, `x.a.b` and `x[i]` root at `x` when `x` is an array. `None` when
/// the path crosses a pointer (`p->a`, `*p`, `p[i]` for a pointer `p`).
fn object_root<'a>(lvalue: Node<'a>, source: &str) -> Option<Node<'a>> {
    match lvalue.kind() {
        "identifier" => Some(lvalue),
        "field_expression" => {
            let through_pointer = lvalue
                .child_by_field_name("operator")
                .is_some_and(|op| get_node_text(&op, source) == "->");
            if through_pointer {
                return None;
            }
            object_root(strip(lvalue.child_by_field_name("argument")?), source)
        }
        "subscript_expression" => {
            let root = object_root(strip(lvalue.child_by_field_name("argument")?), source)?;
            let name = get_node_text(&root, source);
            let (_, declarator) = resolve_identifier_declarator(&root, name, source)?;
            // Indexing a pointer reaches its pointee; indexing an array stays
            // in the array.
            (declarator.kind() == "array_declarator"
                && !matches!(
                    resolve_identifier_binding(&root, name, source),
                    Some(IdentifierBinding::Parameter(_))
                ))
            .then_some(root)
        }
        _ => None,
    }
}

/// `node` without the casts and parentheses around it.
fn strip(node: Node) -> Node {
    match node.kind() {
        "cast_expression" => node.child_by_field_name("value").map_or(node, strip),
        "parenthesized_expression" => node
            .named_children(&mut node.walk())
            .find(|c| c.kind() != "comment")
            .map_or(node, strip),
        _ => node,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utility::cert_c::thread_api::thread_op;
    use lang_parsing_substrate::query;

    fn passed(source: &str) -> Vec<Option<(String, SharedStorage)>> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        query::find_descendants_of_kind(tree.root_node(), "call_expression")
            .iter()
            .filter_map(|c| thread_op(c, source, None))
            .map(|c| passed_object(&c, source).map(|p| (p.name, p.storage)))
            .collect()
    }

    fn auto(name: &str) -> Option<(String, SharedStorage)> {
        Some((name.to_string(), SharedStorage::Automatic))
    }

    #[test]
    fn an_automatic_object_however_its_address_is_written() {
        let got = passed(
            "#include <pthread.h>\n\
             struct s { int a; };\n\
             void *w(void *);\n\
             void f(pthread_t *t, int p) {\n\
               int x; int arr[4]; struct s v;\n\
               pthread_create(t, 0, w, &x);\n\
               pthread_create(t, 0, w, (void *)&(x));\n\
               pthread_create(t, 0, w, arr);\n\
               pthread_create(t, 0, w, &arr[2]);\n\
               pthread_create(t, 0, w, &v.a);\n\
               pthread_create(t, 0, w, &p);\n\
             }",
        );
        assert_eq!(
            got,
            vec![
                auto("x"),
                auto("x"),
                auto("arr"),
                auto("arr"),
                auto("v"),
                auto("p")
            ]
        );
    }

    #[test]
    fn static_allocated_and_pointee_storage_are_not_reported() {
        let got = passed(
            "#include <threads.h>\n\
             struct s { int a; };\n\
             int g; int w(void *);\n\
             void f(thrd_t *t, struct s *ps, int *pi, int pa[]) {\n\
               static int st; extern int ex; int *heap = 0; thrd_t child;\n\
               thrd_create(t, w, &child);\n\
               thrd_create(t, w, &g);\n\
               thrd_create(t, w, &st);\n\
               thrd_create(t, w, &ex);\n\
               thrd_create(t, w, heap);\n\
               thrd_create(t, w, &ps->a);\n\
               thrd_create(t, w, &pi[1]);\n\
               thrd_create(t, w, pa);\n\
               thrd_create(t, w, 0);\n\
             }",
        );
        assert_eq!(got, vec![None; 9]);
    }

    #[test]
    fn a_thread_local_object_is_reported_wherever_it_is_declared() {
        let got = passed(
            "#include <threads.h>\n\
             thread_local int tl; __thread int gnu;\n\
             int w(void *);\n\
             void f(thrd_t *t) { static thread_local int st; \
               thrd_create(t, w, &tl); thrd_create(t, w, &gnu); thrd_create(t, w, &st); }",
        );
        let tl = |n: &str| Some((n.to_string(), SharedStorage::ThreadLocal));
        assert_eq!(got, vec![tl("tl"), tl("gnu"), tl("st")]);
    }
}
