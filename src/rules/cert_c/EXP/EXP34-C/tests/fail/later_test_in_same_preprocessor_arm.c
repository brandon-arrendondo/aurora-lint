/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * Within the #else arm, `q->a` is read before the same arm tests `q` for
 * NULL, so in that build the dereference comes first.
 */
#include <stddef.h>

struct s { int a; };

int get(struct s *q) {
    int v = 0;
#if defined(USE_FAST)
    v = 1;
#else
    v = q->a;
    if (q == NULL)
        return -1;
#endif
    return v;
}
