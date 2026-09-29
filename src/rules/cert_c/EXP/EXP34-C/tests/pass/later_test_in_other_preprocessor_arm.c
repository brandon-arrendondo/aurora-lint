/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * The dereference is in the #if arm and the NULL test in the #else arm.
 * No build compiles both, so the dereference never precedes the test.
 */
#include <stddef.h>

struct s { int a; };

int get(struct s *q) {
    int v = 0;
#if defined(USE_FAST)
    v = q->a;
#else
    if (q == NULL)
        return -1;
    v = q->a;
#endif
    return v;
}
