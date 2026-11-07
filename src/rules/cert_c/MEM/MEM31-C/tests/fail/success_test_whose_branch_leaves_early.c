/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: A branch that returns at its end settles the block only if
 * nothing earlier in it leaves. A break or continue takes the block out of
 * the branch unreleased.
 */

#include <stdlib.h>

int cond(void);

int break_in_the_branch(int n)
{
    char *p;
    for (int i = 0; i < n; i++) {
        p = malloc(8); /* Expect: here */
        if (p) {
            if (cond()) {
                break;
            }
            free(p);
            return 0;
        }
    }
    return 1; /* Expect: here */
}

int continue_in_the_branch(int n)
{
    char *p;
    for (int i = 0; i < n; i++) {
        p = malloc(8); /* Expect: here */
        if (p) {
            if (cond()) {
                continue;
            }
            free(p);
            return 0;
        }
    }
    return 1; /* Expect: here */
}

int break_in_a_branch_that_ends_in_a_jump(int n)
{
    char *p;
    for (int i = 0; i < n; i++) {
        p = malloc(8);
        if (p) {
            if (cond()) {
                break;
            }
            free(p);
            goto out;
        }
    }
    return 1; /* Expect: here */
out:
    return 0;
}

int goto_in_the_branch(void)
{
    char *p = malloc(8); /* Expect: here */
    if (p) {
        if (cond()) {
            goto out; /* Expect: here */
        }
        free(p);
        return 0;
    }
    /* A false report, kept as on base: p is NULL here, but the goto inside
       the branch keeps the test from settling the block. */
    return -1; /* Expect: here */
out:
    return 1; /* Expect: here */
}
