/*
 * Rule: MEM31-C
 * Source: real-world regression
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: A call to a function that never returns ends its branch exactly as
 * `return` does, so the free() before it cannot reach the free() textually
 * after the `if`. Found on four pure-ftpd sites -- pure-pw.c:902,1054,1261
 * and tls.c:301 -- whose allocation-failure branch calls a
 * process-terminating helper before the shared cleanup runs. Covers a plain
 * exit() call and a helper whose body is verified to exit, which hold under
 * every policy. The _Noreturn keyword is covered by
 * noreturn_keyword_branch_not_double_free.c, and a GNU noreturn attribute
 * (proof under neither policy) by
 * fail/gnu_noreturn_attribute_is_not_proof.c.
 */

#include <stdlib.h>

static void die_verified(const char *msg)
{
    (void)msg;
    exit(1);
}

void verified_helper(int cond) {
    char *p = malloc(32);
    if (cond) {
        free(p);
        die_verified("out of memory");
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
