/*
 * Rule: MEM30-C
 * Source: real-world (valkey zmalloc.h: `#define zfree valkey_free`)
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: `zfree` is renamed to `valkey_free` at link time, but the
 * body the scan reads is `void zfree(void *ptr)`, which always frees its
 * argument. The read after `zfree(p)` is a use-after-free.
 */
#include <stdlib.h>

#define zfree valkey_free

void zfree(void *ptr)
{
    free(ptr);
}

int read_after_release(void)
{
    char *p = malloc(16);
    if (p == NULL) {
        return 1;
    }
    p[0] = 'x';
    zfree(p);
    return p[0]; /* VIOLATION */
}
