/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: The `fail:` block inside `if (0) { ... }` returns before
 * control can fall out to the `free(p)` after it, so a jump to `fail`
 * after the allocation leaks `p`, and so does that `return 1` itself.
 * The NULL test's jump has nothing to leak.
 * Expect: count=2
 */
#include <stdlib.h>

int step(void);
void note(void);

int compute(void)
{
    int ret = 0;
    char *p = malloc(8);

    if (p == NULL)
        goto fail;
    if (step() < 0)
        goto fail; /* Expect: here */

    if (0) {
    fail:
        note();
        return 1; /* Expect: here */
    }
    free(p);
    return ret;
}
