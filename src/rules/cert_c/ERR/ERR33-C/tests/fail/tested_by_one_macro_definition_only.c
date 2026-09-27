/*
 * Rule: ERR33-C
 * Status: FAIL - only the DEBUG definition of REQUIRE tests its argument;
 * in every other build it is discarded and the malloc result is used
 * unchecked.
 */

#include <stdlib.h>

extern void die(const char *);

#ifdef DEBUG
#define REQUIRE(x) do { if (!(x)) die("requirement failed"); } while (0)
#else
#define REQUIRE(x) ((void)(x))
#endif

void f(void) {
    char *p = malloc(4);
    REQUIRE(p);
    p[0] = 1;
}
