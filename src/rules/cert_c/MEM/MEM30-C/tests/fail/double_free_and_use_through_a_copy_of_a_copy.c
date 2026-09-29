/*
 * Rule: MEM30-C
 * Source: custom
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: a second free of the same block is a double free, and a use
 * reached through a copy of a copy (`q = p; r = q;`) is a use-after-free,
 * although the alias link is `r -> q`, not `r -> p`.
 */

#include <stdlib.h>

int both_frees_read(void)
{
    char *a = malloc(8);

    if (a == NULL) {
        return 1;
    }
    free(a);
    free(a); /* VIOLATION */
    return 0;
}

int copied_twice_after_read_free(void)
{
    char *p = malloc(8);
    char *q;
    char *r;

    if (p == NULL) {
        return 1;
    }
    free(p);
    q = p;
    r = q;
    return r[0]; /* VIOLATION */
}
