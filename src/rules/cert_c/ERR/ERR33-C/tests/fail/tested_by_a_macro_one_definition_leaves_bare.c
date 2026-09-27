/*
 * Rule: ERR33-C
 * Status: FAIL - every build defines CHECKED, but the non-DEBUG definition
 * is an object-like name, not a test of the argument, so the malloc result
 * is used unchecked in that build.
 */

#include <stdlib.h>

extern void die(const char *);
extern void *checked_identity(void *);

#ifdef DEBUG
#define CHECKED(x) do { if (!(x)) die("requirement failed"); } while (0)
#else
#define CHECKED checked_identity
#endif

void f(void) {
    char *p = malloc(4);
    CHECKED(p);
    p[0] = 1;
}
