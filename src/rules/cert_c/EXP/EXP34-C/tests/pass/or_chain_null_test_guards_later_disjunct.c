/*
 * Rule: EXP34-C
 * Source: real-world shape (sqlite's multi-line asserts)
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * A later disjunct of `p == 0 || x || p->b` is evaluated only when every
 * earlier one was false, so `p == 0` was false and `p` is non-null there.
 * The chain nests to the left, so the null test sits two levels down; an
 * assert's argument is checked like any other expression (ADR-0015 D2), so
 * the same guard must hold there.
 * Settings: free_null_is_noop=true
 *         (the trailing free() is not what this fixture tests)
 */
#include <assert.h>
#include <stdlib.h>

struct L { int b; struct L *next; };

int in_if(int x) {
    struct L *p = malloc(sizeof *p);
    if (p == 0 || x || p->b) {
        free(p);
        return 1;
    }
    free(p);
    return 0;
}

int in_assert(int x) {
    struct L *p = malloc(sizeof *p);
    assert(p == 0 || x || (p->b && p->next == 0));
    free(p);
    return 0;
}
