// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! Whether a call to a C library function has a side effect, in the sense of
//! C11 5.1.2.3p2: it accesses a volatile object, modifies an object or a
//! file, or calls a function that does. Setting `errno` modifies an object,
//! so `strtol` and the math functions have side effects (CERT PRE31-C-EX1:
//! "even changing errno is a side effect").
//!
//! This is the table behind the `stdlib_call_effects` environment contract
//! (`settings::OPTIONS`). It holds only when a conforming library is declared,
//! so ask it only when that option is true; otherwise a library call is a
//! call to an unknown function.

use super::std_functions::is_iso_c_or_posix_function;

/// What the library contract says about one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryEffect {
    /// Modifies no object, touches no stream, keeps no hidden state and never
    /// sets `errno`.
    Pure,
    /// Its only side effect is on the static result buffer it returns (and,
    /// for `strerror`, `errno` on an invalid code): evaluating it zero times
    /// or twice changes nothing a caller observes beyond that buffer. A policy
    /// may relax these (PRE31-C's `pre31_unknown_call_pure`); the contract as
    /// written still counts them.
    OwnBufferOnly,
    /// Has some side effect: writes through an argument, sets `errno`, does
    /// I/O, allocates, or updates hidden state (`rand`, `strtok`).
    SideEffect,
}

/// Library functions that only compute a value from their arguments and the
/// objects those point to. Kept to functions whose specification lists no
/// error reported through `errno` and no object they modify.
const PURE_LIBRARY_FUNCTIONS: &[&str] = &[
    // <string.h> comparison and search (C11 7.24.4, 7.24.5; not strxfrm or
    // strtok, which write, nor strcoll, which POSIX lets set errno to
    // EINVAL), and strlen (7.24.6.3).
    "memcmp",
    "strcmp",
    "strncmp",
    "memchr",
    "strchr",
    "strcspn",
    "strpbrk",
    "strrchr",
    "strspn",
    "strstr",
    "strlen",
    // POSIX <string.h>/<strings.h> read-only counterparts.
    "strnlen",
    "strcasecmp",
    "strncasecmp",
    // <wchar.h> read-only counterparts (C11 7.29.4.4, 7.29.4.5, 7.29.4.6.1).
    "wmemcmp",
    "wcscmp",
    "wcsncmp",
    "wmemchr",
    "wcschr",
    "wcscspn",
    "wcspbrk",
    "wcsrchr",
    "wcsspn",
    "wcsstr",
    "wcslen",
    // <ctype.h> classification and case mapping (C11 7.4).
    "isalnum",
    "isalpha",
    "isblank",
    "iscntrl",
    "isdigit",
    "isgraph",
    "islower",
    "isprint",
    "ispunct",
    "isspace",
    "isupper",
    "isxdigit",
    "tolower",
    "toupper",
    // <wctype.h> (C11 7.30.2).
    "iswalnum",
    "iswalpha",
    "iswblank",
    "iswcntrl",
    "iswdigit",
    "iswgraph",
    "iswlower",
    "iswprint",
    "iswpunct",
    "iswspace",
    "iswupper",
    "iswxdigit",
    "towlower",
    "towupper",
    // POSIX <arpa/inet.h> byte-order conversion.
    "htons",
    "htonl",
    "ntohs",
    "ntohl",
    // <stdlib.h> integer arithmetic (C11 7.22.6).
    "abs",
    "labs",
    "llabs",
    "div",
    "ldiv",
    "lldiv",
    // <math.h> functions with no error condition (C11 7.12.7.2, 7.12.9.1,
    // 7.12.9.2, 7.12.9.6, 7.12.9.8, 7.12.11.1, 7.12.12.2, 7.12.12.3) and the
    // classification macros (7.12.3). Every other math function may report a
    // domain, pole or range error through errno (7.12.1).
    "fabs",
    "fabsf",
    "fabsl",
    "ceil",
    "ceilf",
    "ceill",
    "floor",
    "floorf",
    "floorl",
    "round",
    "roundf",
    "roundl",
    "trunc",
    "truncf",
    "truncl",
    "copysign",
    "copysignf",
    "copysignl",
    "fmax",
    "fmaxf",
    "fmaxl",
    "fmin",
    "fminf",
    "fminl",
    "fpclassify",
    "isfinite",
    "isinf",
    "isnan",
    "isnormal",
    "signbit",
    // Quiet comparison macros (C11 7.12.14: no floating-point exception,
    // no errno) and nan (7.12.11.2, no error condition).
    "isgreater",
    "isgreaterequal",
    "isless",
    "islessequal",
    "islessgreater",
    "isunordered",
    "nan",
    "nanf",
    "nanl",
    // POSIX: getpid "shall always be successful"; pthread_self and
    // pthread_equal report no errors.
    "getpid",
    "pthread_self",
    "pthread_equal",
];

/// Functions whose only side effect is the static buffer they return, a
/// named exception (maintainer rulings on PRE31-C, 2026-09-27). Left out on
/// purpose: ctime and localtime (they may call tzset, which writes tzname
/// and timezone), dlerror (a second call returns NULL: a real state change),
/// inet_ntop and strerror_r (they write the caller's buffer).
const OWN_BUFFER_ONLY_FUNCTIONS: &[&str] = &[
    // C11 7.24.6.2p4: the string "may be overwritten by a subsequent call to
    // the strerror function"; POSIX lets it set errno for an invalid code.
    "strerror",
    // POSIX: the string "may point to static data that may be overwritten by
    // subsequent calls to inet_ntoa()".
    "inet_ntoa",
    // POSIX: the string "might be overwritten by a subsequent call to
    // strsignal()".
    "strsignal",
    // POSIX: returns a pointer to a string describing the error code.
    "gai_strerror",
    // C11 7.22.4.6p4: the string "may be overwritten by a subsequent call to
    // the getenv function".
    "getenv",
    // C11 7.27.3p1: gmtime and asctime return pointers to static objects that
    // a later call to any of the time conversion functions may overwrite.
    "gmtime",
    "asctime",
];

/// The contract's verdict on a call to `name`, or `None` when `name` is not
/// an ISO C or POSIX function the tool knows (a project function, a Windows
/// API, or a library it has no table for). Classify the resolved name (`resolve_macro_alias`),
/// and only when no scanned file defines `name`: a project's own `strlen`
/// is judged by its body.
pub fn library_call_effect(name: &str) -> Option<LibraryEffect> {
    if PURE_LIBRARY_FUNCTIONS.contains(&name) {
        Some(LibraryEffect::Pure)
    } else if OWN_BUFFER_ONLY_FUNCTIONS.contains(&name) {
        Some(LibraryEffect::OwnBufferOnly)
    } else if is_iso_c_or_posix_function(name) {
        Some(LibraryEffect::SideEffect)
    } else {
        None
    }
}

/// ISO C and POSIX objects and constant macros a function body may read
/// without declaring them: a standard header defines each, and system headers
/// are not read, so no scanned file will. Reading one has no side effect.
/// It is the fallback for names nothing in the project declares, never an
/// override: a project defining its own `errno` or `NULL` is judged by that
/// definition. Each group cites where the names are specified.
const STANDARD_OBJECT_NAMES: &[(&str, &[&str])] = &[
    (
        "C11 6.10.8 predefined macro names and 6.4.2.2 `__func__`, plus the GCC spellings of it",
        &[
            "__func__",
            "__FUNCTION__",
            "__PRETTY_FUNCTION__",
            "__FILE__",
            "__LINE__",
            "__DATE__",
            "__TIME__",
            "__STDC__",
            "__STDC_VERSION__",
            "__STDC_HOSTED__",
        ],
    ),
    (
        "C11 7.19 <stddef.h> and 7.18 <stdbool.h>",
        &["NULL", "true", "false", "__bool_true_false_are_defined"],
    ),
    (
        "C11 7.5 <errno.h>: `errno` is a modifiable lvalue, and reading it changes nothing",
        &["errno", "EDOM", "ERANGE", "EILSEQ"],
    ),
    (
        "C11 7.10 <limits.h>",
        &[
            "CHAR_BIT",
            "MB_LEN_MAX",
            "CHAR_MIN",
            "CHAR_MAX",
            "SCHAR_MIN",
            "SCHAR_MAX",
            "UCHAR_MAX",
            "SHRT_MIN",
            "SHRT_MAX",
            "USHRT_MAX",
            "INT_MIN",
            "INT_MAX",
            "UINT_MAX",
            "LONG_MIN",
            "LONG_MAX",
            "ULONG_MAX",
            "LLONG_MIN",
            "LLONG_MAX",
            "ULLONG_MAX",
        ],
    ),
    (
        "C11 7.20.2 <stdint.h> limits",
        &[
            "INT8_MIN",
            "INT8_MAX",
            "INT16_MIN",
            "INT16_MAX",
            "INT32_MIN",
            "INT32_MAX",
            "INT64_MIN",
            "INT64_MAX",
            "INT_LEAST8_MIN",
            "INT_LEAST8_MAX",
            "INT_LEAST16_MIN",
            "INT_LEAST16_MAX",
            "INT_LEAST32_MIN",
            "INT_LEAST32_MAX",
            "INT_LEAST64_MIN",
            "INT_LEAST64_MAX",
            "INT_FAST8_MIN",
            "INT_FAST8_MAX",
            "INT_FAST16_MIN",
            "INT_FAST16_MAX",
            "INT_FAST32_MIN",
            "INT_FAST32_MAX",
            "INT_FAST64_MIN",
            "INT_FAST64_MAX",
            "UINT8_MAX",
            "UINT16_MAX",
            "UINT32_MAX",
            "UINT64_MAX",
            "UINT_LEAST8_MAX",
            "UINT_LEAST16_MAX",
            "UINT_LEAST32_MAX",
            "UINT_LEAST64_MAX",
            "UINT_FAST8_MAX",
            "UINT_FAST16_MAX",
            "UINT_FAST32_MAX",
            "UINT_FAST64_MAX",
            "INTPTR_MIN",
            "INTPTR_MAX",
            "UINTPTR_MAX",
            "INTMAX_MIN",
            "INTMAX_MAX",
            "UINTMAX_MAX",
            "PTRDIFF_MIN",
            "PTRDIFF_MAX",
            "SIG_ATOMIC_MIN",
            "SIG_ATOMIC_MAX",
            "SIZE_MAX",
            "WCHAR_MIN",
            "WCHAR_MAX",
            "WINT_MIN",
            "WINT_MAX",
        ],
    ),
    (
        "C11 5.2.4.2.2 <float.h> and 7.12 <math.h> constants",
        &[
            "FLT_MAX",
            "FLT_MIN",
            "FLT_EPSILON",
            "FLT_DIG",
            "FLT_MANT_DIG",
            "DBL_MAX",
            "DBL_MIN",
            "DBL_EPSILON",
            "DBL_DIG",
            "DBL_MANT_DIG",
            "LDBL_MAX",
            "LDBL_MIN",
            "LDBL_EPSILON",
            "LDBL_DIG",
            "LDBL_MANT_DIG",
            "HUGE_VAL",
            "HUGE_VALF",
            "HUGE_VALL",
            "INFINITY",
            "NAN",
            "FP_NAN",
            "FP_INFINITE",
            "FP_ZERO",
            "FP_SUBNORMAL",
            "FP_NORMAL",
        ],
    ),
    (
        "C11 7.21.1 <stdio.h> macros (the streams are listed separately, hosted only)",
        &[
            "EOF",
            "BUFSIZ",
            "FILENAME_MAX",
            "FOPEN_MAX",
            "L_tmpnam",
            "TMP_MAX",
            "SEEK_SET",
            "SEEK_CUR",
            "SEEK_END",
            "_IOFBF",
            "_IOLBF",
            "_IONBF",
        ],
    ),
    (
        "C11 7.22 <stdlib.h> macros (not MB_CUR_MAX, which glibc expands to a call)",
        &["EXIT_SUCCESS", "EXIT_FAILURE", "RAND_MAX"],
    ),
    (
        "C11 7.14 <signal.h>, 7.11 <locale.h> and 7.27 <time.h> macros",
        &[
            "SIGABRT",
            "SIGFPE",
            "SIGILL",
            "SIGINT",
            "SIGSEGV",
            "SIGTERM",
            "SIG_DFL",
            "SIG_IGN",
            "SIG_ERR",
            "LC_ALL",
            "LC_COLLATE",
            "LC_CTYPE",
            "LC_MONETARY",
            "LC_NUMERIC",
            "LC_TIME",
            "CLOCKS_PER_SEC",
            "TIME_UTC",
        ],
    ),
    (
        "POSIX.1-2017 <errno.h>",
        &[
            "E2BIG",
            "EACCES",
            "EADDRINUSE",
            "EADDRNOTAVAIL",
            "EAFNOSUPPORT",
            "EAGAIN",
            "EALREADY",
            "EBADF",
            "EBUSY",
            "ECANCELED",
            "ECHILD",
            "ECONNABORTED",
            "ECONNREFUSED",
            "ECONNRESET",
            "EDEADLK",
            "EDESTADDRREQ",
            "EEXIST",
            "EFAULT",
            "EFBIG",
            "EHOSTUNREACH",
            "EINPROGRESS",
            "EINTR",
            "EINVAL",
            "EIO",
            "EISCONN",
            "EISDIR",
            "ELOOP",
            "EMFILE",
            "EMLINK",
            "EMSGSIZE",
            "ENAMETOOLONG",
            "ENETDOWN",
            "ENETUNREACH",
            "ENFILE",
            "ENOBUFS",
            "ENODEV",
            "ENOENT",
            "ENOEXEC",
            "ENOLCK",
            "ENOMEM",
            "ENOSPC",
            "ENOSYS",
            "ENOTCONN",
            "ENOTDIR",
            "ENOTEMPTY",
            "ENOTSOCK",
            "ENOTSUP",
            "ENOTTY",
            "ENXIO",
            "EOPNOTSUPP",
            "EOVERFLOW",
            "EPERM",
            "EPIPE",
            "EPROTO",
            "EPROTONOSUPPORT",
            "EROFS",
            "ESPIPE",
            "ESRCH",
            "ETIMEDOUT",
            "EWOULDBLOCK",
            "EXDEV",
        ],
    ),
    (
        "POSIX.1-2017 <unistd.h>, <fcntl.h>, <sys/stat.h> and <limits.h>",
        &[
            "STDIN_FILENO",
            "STDOUT_FILENO",
            "STDERR_FILENO",
            "F_OK",
            "R_OK",
            "W_OK",
            "X_OK",
            "O_RDONLY",
            "O_WRONLY",
            "O_RDWR",
            "O_CREAT",
            "O_EXCL",
            "O_TRUNC",
            "O_APPEND",
            "O_NONBLOCK",
            "O_CLOEXEC",
            "O_NOCTTY",
            "O_SYNC",
            "F_GETFL",
            "F_SETFL",
            "F_GETFD",
            "F_SETFD",
            "FD_CLOEXEC",
            "S_IRUSR",
            "S_IWUSR",
            "S_IXUSR",
            "S_IRWXU",
            "S_IRGRP",
            "S_IWGRP",
            "S_IXGRP",
            "S_IRWXG",
            "S_IROTH",
            "S_IWOTH",
            "S_IXOTH",
            "S_IRWXO",
            "S_IFMT",
            "S_IFREG",
            "S_IFDIR",
            "PATH_MAX",
            "SSIZE_MAX",
        ],
    ),
    (
        "POSIX.1-2017 <signal.h>, <sys/wait.h>, <time.h>, <sys/mman.h>, <poll.h> and <pthread.h>",
        &[
            "SIGHUP",
            "SIGQUIT",
            "SIGKILL",
            "SIGPIPE",
            "SIGALRM",
            "SIGUSR1",
            "SIGUSR2",
            "SIGCHLD",
            "SIGCONT",
            "SIGSTOP",
            "SA_RESTART",
            "SA_SIGINFO",
            "WNOHANG",
            "CLOCK_REALTIME",
            "CLOCK_MONOTONIC",
            "MAP_FAILED",
            "MAP_SHARED",
            "MAP_PRIVATE",
            "MAP_ANONYMOUS",
            "PROT_READ",
            "PROT_WRITE",
            "PROT_EXEC",
            "PROT_NONE",
            "POLLIN",
            "POLLOUT",
            "POLLERR",
            "POLLHUP",
            "POLLNVAL",
            "PTHREAD_MUTEX_INITIALIZER",
            "PTHREAD_COND_INITIALIZER",
        ],
    ),
    (
        "POSIX.1-2017 <sys/socket.h>, <netinet/in.h>, <netinet/tcp.h> and <netdb.h>",
        &[
            "AF_INET",
            "AF_INET6",
            "AF_UNIX",
            "AF_UNSPEC",
            "PF_INET",
            "PF_INET6",
            "SOCK_STREAM",
            "SOCK_DGRAM",
            "SOCK_RAW",
            "SOL_SOCKET",
            "SO_REUSEADDR",
            "SO_ERROR",
            "SO_KEEPALIVE",
            "SO_RCVBUF",
            "SO_SNDBUF",
            "IPPROTO_TCP",
            "IPPROTO_UDP",
            "IPPROTO_IP",
            "IPPROTO_IPV6",
            "TCP_NODELAY",
            "SHUT_RD",
            "SHUT_WR",
            "SHUT_RDWR",
            "MSG_NOSIGNAL",
            "MSG_DONTWAIT",
            "MSG_PEEK",
            "INADDR_ANY",
            "INADDR_LOOPBACK",
            "INADDR_NONE",
            "INET_ADDRSTRLEN",
            "INET6_ADDRSTRLEN",
            "NI_MAXHOST",
            "NI_MAXSERV",
            "FD_SETSIZE",
        ],
    ),
];

/// The standard streams, C11 7.21.1p3: a hosted environment provides them
/// and a freestanding one need not (C11 4p6), so they are known only while
/// the library contract holds.
const HOSTED_STREAM_NAMES: &[&str] = &["stdin", "stdout", "stderr"];

/// What reading a standard name nothing in the project declares is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardName {
    /// A constant or object every environment provides: reading it changes
    /// nothing.
    Constant,
    /// A standard stream, which only a hosted environment provides.
    HostedStream,
}

/// Whether `name` is an ISO C or POSIX object or constant macro, and which
/// kind ([`STANDARD_OBJECT_NAMES`], [`HOSTED_STREAM_NAMES`]). Ask only for a
/// name nothing in the project declares.
pub fn standard_object_name(name: &str) -> Option<StandardName> {
    if HOSTED_STREAM_NAMES.contains(&name) {
        Some(StandardName::HostedStream)
    } else if STANDARD_OBJECT_NAMES
        .iter()
        .any(|(_, names)| names.contains(&name))
    {
        Some(StandardName::Constant)
    } else {
        None
    }
}
