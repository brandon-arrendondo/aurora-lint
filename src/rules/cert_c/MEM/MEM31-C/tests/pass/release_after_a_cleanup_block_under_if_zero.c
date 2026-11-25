/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: The `fail:` label sits inside `if (0) { ... }` and the
 * shared release follows the block. Falling off the end of that block
 * continues after the `if`, so every `goto fail` reaches `free(p)`.
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
        goto fail;
    if (step() > 4)
        goto fail;

    if (0) {
    fail:
        note();
        ret = 1;
    }
    free(p);
    return ret;
}

int compute_in_else(int k)
{
    int ret = 0;
    char *p = malloc(8);

    if (p == NULL)
        goto fail;
    if (step() < 0)
        goto fail;

    if (k) {
        ret = 2;
    } else if (0) {
    fail:
        ret = 1;
    }
    free(p);
    return ret;
}
