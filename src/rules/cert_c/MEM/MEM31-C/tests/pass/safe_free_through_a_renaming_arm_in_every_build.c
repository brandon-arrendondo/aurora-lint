/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * A safe-free macro frees through `xfree`, which one build defines as a
 * function-like macro and the others rename with an object-like
 * `#define xfree counted_free` or `#define xfree free`. In those builds
 * `xfree(ptr)` is a call to the name it renames, and each of them frees,
 * so the block is freed in every build. Reading the renaming arms as
 * unreadable left the free unproven and reported the block leaked.
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

#define safefree(ptr) \
    do {              \
        xfree(ptr);   \
        (ptr) = NULL; \
    } while (0)

void use(void)
{
    char *p = malloc(8);
    if (p == NULL) {
        return;
    }
    safefree(p);
}
