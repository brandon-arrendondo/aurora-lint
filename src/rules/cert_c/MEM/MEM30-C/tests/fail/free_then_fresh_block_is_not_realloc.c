/*
 * Rule: MEM30-C
 * Source: custom
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: `swap` frees its argument and returns a fresh block. That is
 * not realloc's contract: the old block is gone whatever the result, so
 * freeing it again on the NULL branch is a double free.
 */
#include <stdlib.h>

void *swap(void *old, size_t n)
{
    free(old);
    return malloc(n);
}

int replace(void)
{
    char *p = malloc(4);
    char *fresh;

    if (p == NULL) {
        return -1;
    }
    fresh = swap(p, 8);
    if (fresh == NULL) {
        free(p); /* VIOLATION */
        return -1;
    }
    free(fresh);
    return 0;
}
