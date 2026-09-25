/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP34-C violation
 */

/*
 * Rule: EXP34-C - Do not dereference null pointers
 * Status: FAIL
 * Reason: The pointer is assigned inside a null test, but the null branch
 *         does not leave, so the dereference after it is reached with `p`
 *         null. Recognizing `(p = malloc(n))` as a test of `p` must not
 *         clear a guard that guards nothing.
 */

#include <stdlib.h>

struct obj {
    int x;
};

int guard_falls_through(void)
{
    struct obj *p;
    if (!(p = malloc(sizeof *p))) {
        /* logged, but not handled */
    }
    p->x = 1;
    free(p);
    return 0;
}
