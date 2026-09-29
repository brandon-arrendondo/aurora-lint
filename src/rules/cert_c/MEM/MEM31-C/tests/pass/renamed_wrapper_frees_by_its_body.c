/*
 * Rule: MEM31-C
 * Source: real-world (valkey zmalloc.h: `#define zfree valkey_free`)
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: `zfree` is renamed to `valkey_free` at link time, but the
 * body the scan reads is `void zfree(void *ptr)`. Resolving the call all the
 * way to `valkey_free` finds no body; the alias chain is followed only as far
 * as the first name with one, so `zfree(p)` frees `p` by its body.
 */
#include <stdlib.h>

#define zfree valkey_free

void zfree(void *ptr)
{
    free(ptr);
}

void release(void)
{
    char *p = malloc(16);
    if (p == NULL) {
        return;
    }
    zfree(p);
}
