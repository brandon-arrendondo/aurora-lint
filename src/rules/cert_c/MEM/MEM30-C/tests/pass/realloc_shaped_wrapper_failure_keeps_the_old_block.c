/*
 * Rule: MEM30-C
 * Source: real-world (hostap os_realloc_array under WPA_TRACE)
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: `grow` releases its first argument and hands back a fresh
 * block, so it is realloc by what its body does. When it returns NULL the
 * old block is still the caller's, and freeing it on that branch is not a
 * double free.
 */
#include <stdlib.h>
#include <string.h>

void *grow(void *ptr, size_t n)
{
    void *fresh = malloc(n);
    if (fresh == NULL) {
        return NULL;
    }
    memcpy(fresh, ptr, 1);
    free(ptr);
    return fresh;
}

int extend(void)
{
    char *buf = malloc(4);
    char *bigger;

    if (buf == NULL) {
        return -1;
    }
    bigger = grow(buf, 8);
    if (bigger == NULL) {
        free(buf);
        return -1;
    }
    free(bigger);
    return 0;
}
