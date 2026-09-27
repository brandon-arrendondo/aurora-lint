/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: RE is realloc when OWN_ALLOC is undefined, and there
 * RE(p, n) releases p, so the free(p) that follows frees it twice.
 */

#include <stdlib.h>

void *my_realloc(void *p, size_t n);

#ifdef OWN_ALLOC
#define RE my_realloc
#else
#define RE realloc
#endif

void f(size_t n)
{
    char *p = malloc(8);
    if (p == NULL)
        return;
    RE(p, n);
    free(p);
}
