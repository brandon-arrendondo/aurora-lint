/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM30-C violation
 */

/*
 * Rule: MEM30-C - Do not access freed memory
 * Status: PASS
 * Reason: A free inside a branch that DIVERGES (does not fall through to the
 *         code after the if) must not propagate the freed state. Besides
 *         `return`, this covers `goto`, `break`, and `continue`. Error paths in
 *         real C free-then-`goto cleanup` / free-then-`break`; a sibling branch
 *         doing the same is NOT a double-free, and the post-loop / post-if use
 *         is NOT a use-after-free, because only one branch executes (task 181
 *         pattern 2). Previously only `return` was recognized as a terminator.
 */

#include <stdlib.h>

extern int op_a(char *p);
extern int op_b(char *p);

/* goto-terminated error branches (curl ldap.c / fopen.c idiom). */
int free_then_goto(char *temp) {
    int rc = 0;
    if (op_a(temp)) {
        free(temp);
        goto cleanup;        /* diverges - state must not propagate */
    }
    if (op_b(temp)) {        /* not use-after-free */
        free(temp);          /* not double-free */
        goto cleanup;
    }
    return 0;
cleanup:
    return rc;
}

/* break-terminated branches inside a loop. */
int free_then_break(char *p) {
    for (;;) {
        if (op_a(p)) {
            free(p);
            break;           /* diverges */
        }
        if (op_b(p)) {       /* not use-after-free */
            free(p);         /* not double-free */
            break;
        }
        return 1;
    }
    return 0;
}

/* continue-terminated branch inside a loop. */
void free_then_continue(char **list, int n) {
    int i;
    for (i = 0; i < n; i++) {
        char *p = list[i];
        if (op_a(p)) {
            free(p);
            continue;        /* diverges to next iteration */
        }
        op_b(p);             /* not use-after-free: distinct path */
    }
}
