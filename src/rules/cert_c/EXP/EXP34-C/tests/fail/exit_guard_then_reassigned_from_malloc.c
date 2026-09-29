/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * The earlier test does leave, but it tested a different value: `p` is
 * reassigned from malloc() after it, and that result is dereferenced
 * unchecked.
 */
#include <stdlib.h>

struct s { int a; };
struct s *get(void);

int reassigned(void) {
    struct s *p = get();
    if (p == NULL) {
        return -1;
    }
    p = malloc(sizeof *p);
    return p->a;
}
