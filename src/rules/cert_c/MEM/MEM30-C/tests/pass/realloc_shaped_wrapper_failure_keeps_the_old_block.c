/*
 * Rule: MEM30-C
 * Source: real-world (hostap os.h: `os_realloc_array` returns
 *         `os_realloc(ptr, nmemb * size)`)
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: `grow` returns realloc called on its first parameter, so it
 * follows realloc's contract by proof. When it returns NULL the old block is
 * still the caller's, and freeing it on that branch is not a double free.
 */
#include <stdlib.h>

void *grow(void *ptr, size_t nmemb, size_t size)
{
    return realloc(ptr, nmemb * size);
}

int extend(void)
{
    char *buf = malloc(4);
    char *bigger;

    if (buf == NULL) {
        return -1;
    }
    bigger = grow(buf, 8, 1);
    if (bigger == NULL) {
        free(buf);
        return -1;
    }
    free(bigger);
    return 0;
}
