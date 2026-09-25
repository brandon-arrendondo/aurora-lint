/*
 * Rule: EXP34-C - Do not dereference null pointers
 * Status: FAIL - Should trigger EXP34-C violation
 * Reason: A plain assert() is not a null guard. NDEBUG strips it, and in that
 *         configuration nothing stands between malloc's possible NULL and the
 *         dereference (ADR-0010 D5). Each function below dereferences p
 *         after the assert and is a violation. A dereference inside the
 *         assert's own condition proves nothing either: it runs before the
 *         check, so it is not one (ADR-0011).
 *         This file was once a PASS fixture for the reverse policy.
 */

#include <stdlib.h>
#include <assert.h>

struct Mem {
    int flags;
    int n;
};

/* assert(p != 0) is gone under NDEBUG. */
void explicit_assert(int n) {
    struct Mem *p = malloc(sizeof(struct Mem));
    assert(p != 0);
    p->flags = n; /* violation: p may be NULL */
}

/* assert(p) is gone under NDEBUG. */
void truthy_assert(int n) {
    struct Mem *p = malloc(sizeof(struct Mem));
    assert(p);
    p->n = n; /* violation: p may be NULL */
}

/* The assert dereferences p itself, which checks nothing, and is gone
 * under NDEBUG anyway. */
void implicit_deref_assert(int n) {
    struct Mem *p = malloc(sizeof(struct Mem));
    assert((p->flags & 1) == 0);
    p->flags |= 2; /* violation: p may be NULL */
}
