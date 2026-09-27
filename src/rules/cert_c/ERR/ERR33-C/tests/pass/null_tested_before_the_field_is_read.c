/*
 * Rule: ERR33-C
 * Status: PASS - `p && p->len > 0` tests p before reading through it.
 */

#include <stdlib.h>

struct s { int len; };

int f(size_t n) {
    struct s *p = malloc(n);
    if (p && p->len > 0) {
        return 1;
    }
    return 0;
}
