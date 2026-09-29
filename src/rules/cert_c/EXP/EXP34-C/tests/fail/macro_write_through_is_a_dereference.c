/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * INIT_V(p) expands to `(p)->x = 0`: a write through `p`, which is a
 * dereference of an unchecked malloc() result at the invocation line. The
 * write proves nothing about `p`. It is the site, and the macro has no body
 * of its own for the dereference to be reported in.
 */
#include <stdlib.h>

struct v { int x; };
#define INIT_V(q) do { (q)->x = 0; } while (0)

void make(void) {
    struct v *p = malloc(sizeof *p);
    INIT_V(p);
    p->x = 1;
    free(p);
}
