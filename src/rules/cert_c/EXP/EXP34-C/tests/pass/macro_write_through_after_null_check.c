/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * The same write-through macro, reached only after the NULL branch has
 * returned.
 */
#include <stdlib.h>

struct v { int x; };
#define INIT_V(q) do { (q)->x = 0; } while (0)

void make(void) {
    struct v *p = malloc(sizeof *p);
    if (p == NULL)
        return;
    INIT_V(p);
    p->x = 1;
    free(p);
}
