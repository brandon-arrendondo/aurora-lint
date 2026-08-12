/*
 * Rule: DCL30-C
 * Status: PASS - Local declared with no initializer, then assigned from a
 * non-alloc-named heap-returning wrapper before being returned (valid)
 */

#include <stdlib.h>

struct thing {
    int x;
};

static struct thing *make_thing(int x) {
    struct thing *t = malloc(sizeof(*t));
    if (t)
        t->x = x;
    return t;
}

struct thing *build(int x) {
    struct thing *t;

    t = make_thing(x);
    if (!t)
        return NULL;

    return t;  /* Safe: t holds a heap-derived pointer value */
}
