/*
 * Rule: ERR33-C
 * Status: FAIL - REQUIRE is defined only when DEBUG is; a build without it
 * has no such macro, so the null test cannot be relied on and the malloc
 * result is used unchecked there.
 */

#include <stdlib.h>

extern void die(const char *);
extern void REQUIRE(void *);

#ifdef DEBUG
#define REQUIRE(x) do { if (!(x)) die("requirement failed"); } while (0)
#endif

void f(void) {
    char *p = malloc(4);
    REQUIRE(p);
    p[0] = 1;
}
