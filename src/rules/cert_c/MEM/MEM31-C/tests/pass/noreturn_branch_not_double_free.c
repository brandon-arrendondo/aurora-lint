/*
 * Rule: MEM31-C
 * Source: task_1076
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: A call to a function that never returns ends its branch exactly as
 * `return` does, so the free() before it cannot reach the free() textually
 * after the `if`. Covers all four spellings the shared noreturn detection
 * recognizes: a trailing __attribute__((noreturn)) (pure-ftpd's own form in
 * ftpd.h), a leading one, the _Noreturn keyword, and a plain exit() call.
 * Found on four pure-ftpd sites -- pure-pw.c:902,1054,1261 and tls.c:301 --
 * whose allocation-failure branch calls a process-terminating helper before
 * the shared cleanup runs (task 1076).
 */

#include <stdlib.h>

static void die_trailing(const char *msg) __attribute__((noreturn));
static __attribute__((noreturn)) void die_leading(const char *msg);
static _Noreturn void die_keyword(const char *msg);

void trailing_attribute(int cond) {
    char *p = malloc(32);
    if (cond) {
        free(p);
        die_trailing("out of memory");
    }
    free(p);
}

void leading_attribute(int cond) {
    char *p = malloc(32);
    if (cond) {
        free(p);
        die_leading("out of memory");
    }
    free(p);
}

void noreturn_keyword(int cond) {
    char *p = malloc(32);
    if (cond) {
        free(p);
        die_keyword("out of memory");
    }
    free(p);
}

void stdlib_exit(int cond) {
    char *p = malloc(32);
    if (cond) {
        free(p);
        exit(1);
    }
    free(p);
}
