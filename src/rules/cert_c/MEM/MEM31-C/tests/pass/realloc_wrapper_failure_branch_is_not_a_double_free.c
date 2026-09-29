/*
 * Rule: MEM31-C
 * Source: real-world (hostap utils/common.c freq_range_list_parse:
 *         `n = os_realloc_array(freq, ...); if (n == NULL) { os_free(freq);
 *         return -1; }`)
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: `grow_array` returns realloc called on its first parameter,
 * so it follows realloc's contract; the tracing build's copy-and-free arm
 * (hostap's WPA_TRACE os_realloc) makes the free of `ptr` look certain, but
 * a NULL result still leaves the old block with the caller, which frees it
 * once: no double free, and the grown block is kept, then freed, so no leak.
 */
#include <stdlib.h>
#include <string.h>

void *grow_array(void *ptr, size_t nmemb, size_t size)
{
#ifdef ALLOC_TRACE
    void *n = malloc(nmemb * size);
    memcpy(n, ptr, 1);
    free(ptr);
    return n;
#else
    return realloc(ptr, nmemb * size);
#endif
}

int collect(int count)
{
    int *freq = NULL;
    int *n;
    int i;

    for (i = 0; i < count; i++) {
        n = grow_array(freq, (size_t)i + 1, sizeof(int));
        if (n == NULL) {
            free(freq);
            return -1;
        }
        freq = n;
        freq[i] = i;
    }
    free(freq);
    return 0;
}
