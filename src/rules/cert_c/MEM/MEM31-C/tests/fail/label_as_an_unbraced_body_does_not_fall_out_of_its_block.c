/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: `fail:` is the unbraced body of `if (0)`, which sits in the
 * block of `if (a)`. Falling off the label's statement continues with the
 * `return ret;` in that block, not with the `free(p)` after it, so the jump
 * past the allocation check leaks `p`, and so does that return.
 * Expect: count=2
 */
#include <stdlib.h>

int step(void);

int compute(int a)
{
    int ret = 0;
    char *p = malloc(8);

    if (p == NULL)
        goto fail;
    if (step() < 0)
        goto fail; /* Expect: here */

    if (a) {
        if (0)
        fail:
            ret = 1;
        return ret; /* Expect: here */
    }
    free(p);
    return ret;
}
