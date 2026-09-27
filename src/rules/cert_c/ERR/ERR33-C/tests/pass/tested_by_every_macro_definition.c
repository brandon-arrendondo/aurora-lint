/*
 * Rule: ERR33-C
 * Status: PASS - both definitions of REQUIRE test their argument, one by
 * aborting and one by returning, so every build null-tests the malloc
 * result before it is used.
 */

#include <stdlib.h>

extern void die(const char *);

#ifdef DEBUG
#define REQUIRE(x) do { if (!(x)) die("requirement failed"); } while (0)
#else
#define REQUIRE(x) do { if (!(x)) return; } while (0)
#endif

void f(void) {
    char *p = malloc(4);
    REQUIRE(p);
    p[0] = 1;
}
