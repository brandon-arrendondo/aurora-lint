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
//! or receive whose flags always set `MSG_DONTWAIT` (the flag itself, or a
//! term of a bitwise OR) does not block (CERT's compliant solution). A descriptor made non-blocking with `O_NONBLOCK`
//! elsewhere is not visible at the call.

use crate::settings::threads::ThreadOpKind;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::mutex_lifetime::{self, HeldLock};
use crate::utility::cert_c::thread_api::{self, ProjectFunctions};
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
        if args
            .get(position - 1)
            .is_some_and(|flags| sets_dontwait(*flags, source))
        {
            return None;
        }
    }
    Some(name.to_string())
}

/// Whether the flags expression `flags` always sets `MSG_DONTWAIT`: it is
/// `MSG_DONTWAIT` itself, or a term of a bitwise OR, through parentheses.
/// Under `~`, `&` or `?:` the bit may be clear. A variable or macro that
/// holds it is not followed, so such a call stays reported.
fn sets_dontwait(flags: Node, source: &str) -> bool {
    match flags.kind() {
        "identifier" => get_node_text(&flags, source) == "MSG_DONTWAIT",
        "parenthesized_expression" => flags
            .named_child(0)
            .is_some_and(|inner| sets_dontwait(inner, source)),
        "binary_expression" => {
            let or = flags
                .child_by_field_name("operator")
                .is_some_and(|o| get_node_text(&o, source) == "|");
            or && ["left", "right"].iter().any(|side| {
                flags
                    .child_by_field_name(side)
                    .is_some_and(|term| sets_dontwait(term, source))
            })
        }
        _ => false,
    }
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
    fn a_lock_in_a_condition_is_held_where_it_succeeded() {
        let got = blocking(
            "#include <pthread.h>\n\
             #include <unistd.h>\n\
             pthread_mutex_t m;\n\
             int f(int x, int fd, char *b) {\n\
               if (x && pthread_mutex_lock(&m) == 0) { pthread_mutex_unlock(&m); } else { write(fd, b, 1); }\n\
               x && pthread_mutex_lock(&m);\n\
               write(fd, b, 1);\n\
               if (pthread_mutex_lock(&m) != 0) { write(fd, b, 2); return -1; }\n\
               write(fd, b, 3);\n\
               pthread_mutex_unlock(&m);\n\
               if (!pthread_mutex_lock(&m)) { write(fd, b, 4); pthread_mutex_unlock(&m); }\n\
               if ((x = pthread_mutex_lock(&m)) != 0) { write(fd, b, 5); }\n\
               write(fd, b, 6);\n\
               pthread_mutex_unlock(&m);\n\
               if (pthread_mutex_lock(&m) == 22) { write(fd, b, 7); }\n\
               write(fd, b, 8);\n\
               return 0;\n\
             }",
        );
        let lines: Vec<usize> = got.into_iter().map(|(line, _, _)| line).collect();
        assert_eq!(lines, vec![9, 11, 13]);
    }

    #[test]
    fn msg_dontwait_exempts_only_as_a_term_of_an_or() {
        let got = blocking(
            "#include <pthread.h>\n\
             #include <sys/socket.h>\n\
             pthread_mutex_t m;\n\
             void f(int s, char *b, int c, int fl) {\n\
               pthread_mutex_lock(&m);\n\
               recv(s, b, 1, fl & ~MSG_DONTWAIT);\n\
               recv(s, b, 1, c ? MSG_DONTWAIT : 0);\n\
               recv(s, b, 1, fl);\n\
               recv(s, b, 1, MSG_PEEK | (MSG_DONTWAIT));\n\
               recv(s, b, 1, fl | MSG_DONTWAIT);\n\
               pthread_mutex_unlock(&m);\n\
             }",
        );
        let lines: Vec<usize> = got.into_iter().map(|(line, _, _)| line).collect();
        assert_eq!(lines, vec![6, 7, 8]);
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
