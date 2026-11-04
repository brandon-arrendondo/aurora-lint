/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * A safe-free macro frees through `xfree`, which one build defines as a
 * function-like macro and the others rename with an object-like `#define`.
 * In the BUILDING_LIBRARY build it renames `trace_only`, whose body does
 * not free. A renaming arm is read as the call it makes, so that build
 * leaks, and a leak is withheld only on what every build agrees on.
 */
#include <stdlib.h>

void trace_only(void *ptr)
{
    (void)ptr;
}

#ifdef DEBUGBUILD
#define MEMDEBUG
#endif

#ifdef MEMDEBUG
#define xfree(ptr) free(ptr)
#else
#ifdef BUILDING_LIBRARY
#define xfree trace_only
#else
#define xfree free
#endif
#endif

#define safefree(ptr) \
    do {              \
        xfree(ptr);   \
        (ptr) = NULL; \
    } while (0)

void use(void)
{
    /* VIOLATION: not freed in the BUILDING_LIBRARY build */
    char *p = malloc(8);
    if (p == NULL) {
        return;
    }
    safefree(p);
}
