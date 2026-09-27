/*
 * Rule: ERR33-C
 * Status: PASS - REQUIRE(p) expands to `if (!(p)) die(...)`, a null test of
 * the malloc result before it is used.
 */

#include <stdlib.h>

extern void die(const char *);

#define REQUIRE(x) do { if (!(x)) die("requirement failed"); } while (0)

void f(void) {
    char *p = malloc(4);
    REQUIRE(p);
    p[0] = 1;
}
