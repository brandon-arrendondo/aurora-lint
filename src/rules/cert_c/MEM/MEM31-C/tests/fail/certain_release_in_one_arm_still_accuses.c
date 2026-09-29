/*
 * Rule: MEM31-C
 * Source: review regression
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: one arm frees `p` outright and the other hands it to a
 * callee that frees it on some paths only. Below the `if`, the free() that
 * follows is a double free on the first arm's path. A release that cannot
 * accuse in one arm does not excuse a certain one in the other.
 */
#include <stdlib.h>

void maybe_release(char *p, int k)
{
    if (k)
        free(p);
}

void settle(int c, int k)
{
    char *p = malloc(16);
    if (p == NULL)
        return;
    if (c)
        free(p);
    else
        maybe_release(p, k);
    free(p);
}
