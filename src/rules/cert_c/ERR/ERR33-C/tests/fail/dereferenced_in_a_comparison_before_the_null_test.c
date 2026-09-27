/*
 * Rule: ERR33-C
 * Status: FAIL - `p->len > 0` reads through the malloc result before
 * `if (!p)` tests it: the comparison is a use of p, not a test of it.
 */

#include <stdlib.h>

struct s { int len; };

int f(size_t n) {
    struct s *p = malloc(n);
    if (p->len > 0) {
        return 2;
    }
    if (!p) {
        return 1;
    }
    return 0;
}
