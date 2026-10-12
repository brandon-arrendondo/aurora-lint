// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! Calls that can block, made while a mutex is held: the one analysis CON05-C
//! (every family) and POS52-C (POSIX) share.
//!
//! The lock regions are [`mutex_lifetime::calls_under_lock`]'s: a mutex
//! counts as held at a call only when a lock that waits for it is held on
//! every path to the call. Every call in a statement is read, not only the
//! first.
//!
//! A call can block when it is a thread-API sleep (any family), or a call
//! that reaches the C or POSIX library function (not one the project defines
//! itself, [`thread_api::library_call`]) of a name in [`BLOCKING`]. Acquiring
//! another mutex is not counted here: lock order is CON35-C's. A socket send
//! or receive whose flags include `MSG_DONTWAIT` does not block (CERT's
//! compliant solution). A descriptor made non-blocking with `O_NONBLOCK`
//! elsewhere is not visible at the call.

use crate::settings::threads::ThreadOpKind;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::mutex_lifetime::{self, HeldLock};
use crate::utility::cert_c::thread_api::{self, ProjectFunctions};
use lang_parsing_substrate::query;
use tree_sitter::Node;

/// Library functions the C or POSIX standard lets block the caller
/// indefinitely: stream, descriptor and socket I/O, and waits.
pub const BLOCKING: &[&str] = &[
    // Stream I/O
    "fopen",
    "fclose",
    "fread",
    "fwrite",
    "fprintf",
    "fscanf",
    "fgets",
    "fputs",
    "fgetc",
    "fputc",
    "fflush",
    "printf",
    "scanf",
    "puts",
    "gets",
    "getchar",
    "putchar",
    // Descriptor I/O
    "open",
    "close",
    "read",
    "write",
    // Sockets and readiness
    "send",
    "recv",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "connect",
    "accept",
    "select",
    "poll",
    "epoll_wait",
    // Waits
    "sleep",
    "usleep",
    "nanosleep",
    "wait",
    "waitpid",
    "pause",
];

/// The flags argument's 1-based position for the socket calls that take one.
fn flags_position(name: &str) -> Option<usize> {
    match name {
        "send" | "recv" | "sendto" | "recvfrom" => Some(4),
        "sendmsg" | "recvmsg" => Some(3),
        _ => None,
    }
}

/// A call that can block, made under a lock.
pub struct BlockingCall<'a> {
    /// The call expression.
    pub node: Node<'a>,
    /// The function called.
    pub callee: String,
    /// The mutexes held there, earliest lock first.
    pub held: Vec<HeldLock>,
}

/// Every call in the file under `root` that can block while a mutex is held,
/// in source order.
pub fn blocking_under_lock<'a>(
    root: &Node<'a>,
    source: &str,
    project: Option<&ProjectFunctions>,
) -> Vec<BlockingCall<'a>> {
    mutex_lifetime::calls_under_lock(root, source, project)
        .into_iter()
        .filter_map(|under| {
            let callee = blocking_callee(&under.node, source, project)?;
            Some(BlockingCall {
                node: under.node,
                callee,
                held: under.held,
            })
        })
        .collect()
}

/// The function `call` calls, when that call can block.
fn blocking_callee(
    call: &Node,
    source: &str,
    project: Option<&ProjectFunctions>,
) -> Option<String> {
    if let Some(op) = thread_api::thread_op(call, source, project) {
        return (op.kind() == ThreadOpKind::Sleep).then_some(op.name);
    }
    let name = thread_api::library_call(call, source, project)?;
    if !BLOCKING.contains(&name) {
        return None;
    }
    if let Some(position) = flags_position(name) {
        let args: Vec<Node> = call
            .child_by_field_name("arguments")
            .map(|list| {
                list.named_children(&mut list.walk())
                    .filter(|n| n.kind() != "comment")
                    .collect()
            })
            .unwrap_or_default();
        let nonblocking = args.get(position - 1).is_some_and(|flags| {
            let mut idents = query::find_descendants_of_kind(*flags, "identifier");
            idents.push(*flags);
            idents
                .iter()
                .any(|id| id.kind() == "identifier" && get_node_text(id, source) == "MSG_DONTWAIT")
        });
        if nonblocking {
            return None;
        }
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocking(source: &str) -> Vec<(usize, String, Vec<String>)> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        blocking_under_lock(&tree.root_node(), source, None)
            .into_iter()
            .map(|b| {
                (
                    b.node.start_position().row + 1,
                    b.callee,
                    b.held.into_iter().map(|h| h.mutex).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn every_blocking_call_under_a_lock_held_on_every_path() {
        let got = blocking(
            "#include <pthread.h>\n\
             #include <sys/socket.h>\n\
             pthread_mutex_t m;\n\
             void f(int s, char *b, int c) {\n\
               if (c) { pthread_mutex_lock(&m); }\n\
               recv(s, b, 1, 0);\n\
               pthread_mutex_lock(&m);\n\
               if (recv(s, b, 1, 0) < 0 && send(s, b, 1, 0) < 0) {}\n\
               recv(s, b, 1, MSG_DONTWAIT | MSG_PEEK);\n\
               pthread_mutex_unlock(&m);\n\
               send(s, b, 1, 0);\n\
             }",
        );
        assert_eq!(
            got,
            vec![
                (8, "recv".into(), vec!["m".into()]),
                (8, "send".into(), vec!["m".into()]),
            ]
        );
    }

    #[test]
    fn a_lock_and_a_project_definition_do_not_block() {
        let got = blocking(
            "#include <threads.h>\n\
             mtx_t a, b;\n\
             int read(int fd, void *p, unsigned n) { return 0; }\n\
             void f(int fd, char *p) {\n\
               mtx_lock(&a);\n\
               mtx_lock(&b);\n\
               read(fd, p, 1);\n\
               thrd_sleep(0, 0);\n\
               mtx_unlock(&b);\n\
               mtx_unlock(&a);\n\
             }",
        );
        assert_eq!(
            got,
            vec![(8, "thrd_sleep".into(), vec!["a".into(), "b".into()])]
        );
    }
}
