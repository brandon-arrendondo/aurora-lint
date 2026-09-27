/*
 * Rule: ERR33-C
 * Status: FAIL - the macro writes through its argument before testing it,
 * so the malloc result is used before the null test.
 */

#include <stdlib.h>

struct s { int n; };

#define RESET(x) do { (x)->n = 0; if (!(x)) abort(); } while (0)

void f(void) {
    struct s *p = malloc(sizeof *p);
    RESET(p);
}
