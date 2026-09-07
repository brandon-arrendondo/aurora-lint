/*
 * Rule: DCL31-C
 * Source: task 1038 (pure-ftpd src/ftpd.c, src/pure-quotacheck.c)
 * Status: PASS - a prototype decorated with a trailing attribute macro is
 * still a declaration, so calling the function it declares is not an
 * implicit declaration.
 *
 * glibc writes most of POSIX this way -- `extern int sigaction (...) __THROW;`
 * in <signal.h>, `extern int setuid (...) __THROW __wur;` in <unistd.h>.
 * `__THROW` expands from <sys/cdefs.h>, which is not part of this parse, so
 * tree-sitter cannot finish the declaration and wraps the whole thing in an
 * ERROR node holding the specifiers and the function_declarator -- with no
 * `declaration` node anywhere inside it. A walk that only visits
 * `declaration`/`function_definition` therefore reads the entire POSIX
 * signal/process API as undeclared.
 *
 * Note the pointer-returning form parses cleanly as a `declaration` and was
 * never affected; it is here so the fixture covers both halves.
 */

typedef struct sigset_t_ sigset_t;

extern int sigemptyset (sigset_t *set) __THROW __nonnull ((1));
extern int sigaction (int sig, const struct sigaction *act,
                      struct sigaction *oact) __THROW;
extern int setuid (int uid) __THROW __wur;
extern char *pure_strdup (const char *s) __THROW __attribute_malloc__;

void install_handlers(sigset_t *set)
{
    sigemptyset(set);
    sigaction(2, 0, 0);
    setuid(0);
    (void)pure_strdup("x");
}
