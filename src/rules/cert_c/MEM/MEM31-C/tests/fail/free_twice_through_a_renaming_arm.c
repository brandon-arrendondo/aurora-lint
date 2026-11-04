/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * `xfree` frees in every build: once as a function-like macro, otherwise
 * through an object-like arm renaming `counted_free` or `free`. Calling
 * it twice on one block is a double free in each of them.
 */
#include <stdlib.h>

void counted_free(void *ptr)
{
    free(ptr);
}

#ifdef DEBUGBUILD
#define MEMDEBUG
#endif

#ifdef MEMDEBUG
#define xfree(ptr) free(ptr)
#else
#ifdef BUILDING_LIBRARY
#define xfree counted_free
#else
#define xfree free
#endif
#endif

void use(void)
{
    char *p = malloc(8);
    if (p == NULL) {
        return;
    }
    xfree(p);
    xfree(p); /* Expect: here */
}
