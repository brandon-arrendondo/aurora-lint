// sqc-test: prescan
/*
 * Rule: EXP34-C - Do not dereference null pointers
 * Status: PASS - Should NOT trigger EXP34-C violation
 * Reason: A pointer established non-null by a dominating assert() precondition
 *         (the sqlite documented-invariant idiom) is non-null at later derefs.
 *         Task 207, EXP34-C caller-contract / precondition bucket.
 */

#include <stdlib.h>
#include <assert.h>

struct Mem {
    int flags;
    int n;
};

/* Explicit precondition: assert(p != 0) documents the non-null invariant. */
void explicit_assert(int n) {
    struct Mem *p = malloc(sizeof(struct Mem));
    assert(p != 0);
    p->flags = n; /* safe: established non-null by the assert above */
}

/* Bare-truthiness precondition: assert(p). */
void truthy_assert(int n) {
    struct Mem *p = malloc(sizeof(struct Mem));
    assert(p);
    p->n = n; /* safe */
}

/* Implicit precondition: the assert itself dereferences p (no ||/ternary),
 * so p must be non-null when the assert holds. */
void implicit_deref_assert(int n) {
    struct Mem *p = malloc(sizeof(struct Mem));
    assert((p->flags & 1) == 0);
    p->flags |= 2; /* safe: assert already required p non-null */
}
