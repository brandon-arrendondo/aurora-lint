/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: app_calloc is the project's own allocator hook under
 * CUSTOM_ALLOC and plain calloc otherwise (mbedtls's mbedtls_calloc
 * shape). In the calloc build, the block f() allocates is leaked on the
 * early return. An alias that is an allocator in one build allocates in
 * that build.
 */

#include <stdlib.h>

void *custom_alloc_hook(size_t n, size_t size);
int step(char *buf);

#ifdef CUSTOM_ALLOC
#define app_calloc custom_alloc_hook
#else
#define app_calloc calloc
#endif

int f(void)
{
    char *buf = app_calloc(1, 16);
    if (buf == NULL)
        return -1;
    if (step(buf) != 0)
        return -1;
    free(buf);
    return 0;
}
