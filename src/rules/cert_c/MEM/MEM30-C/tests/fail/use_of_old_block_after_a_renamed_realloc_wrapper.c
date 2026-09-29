/*
 * Rule: MEM30-C
 * Source: real-world (valkey zmalloc.h: `#define zrealloc valkey_realloc`)
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: `zrealloc` is renamed at link time, but the body the scan
 * reads is `zrealloc`'s, which returns realloc called on its first
 * parameter. Once the call has succeeded the old pointer no longer names a
 * live block, so reading through it is a use-after-free.
 */
#include <stdlib.h>

#define zrealloc valkey_realloc

void *zrealloc(void *ptr, size_t n)
{
    return realloc(ptr, n);
}

int grow(void)
{
    char *p = malloc(4);
    char *q;

    if (p == NULL) {
        return -1;
    }
    q = zrealloc(p, 64);
    if (q != NULL) {
        int c = p[0]; /* VIOLATION */
        free(q);
        return c;
    }
    free(p);
    return 0;
}
