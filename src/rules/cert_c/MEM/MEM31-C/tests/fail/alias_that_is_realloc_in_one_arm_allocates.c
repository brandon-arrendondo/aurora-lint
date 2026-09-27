/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: RE is realloc when OWN_ALLOC is undefined. Where it is,
 * q = RE(NULL, n) allocates a block that is never freed. An alias that is
 * an allocator in one build allocates there.
 */

#include <stdlib.h>

void *my_realloc(void *p, size_t n);

#ifdef OWN_ALLOC
#define RE my_realloc
#else
#define RE realloc
#endif

int f(size_t n)
{
    char *q = RE(NULL, n);
    if (q == NULL)
        return -1;
    q[0] = 0;
    return 0;
}
