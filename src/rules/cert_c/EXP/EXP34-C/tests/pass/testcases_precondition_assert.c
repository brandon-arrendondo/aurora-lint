/*
 * Rule: EXP34-C - Do not dereference null pointers
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 * Reason: A pointer established non-null by a dominating assert() precondition
 *         (the sqlite documented-invariant idiom) is non-null at later derefs
 *         when the policy credits an assert as a guard (assert_is_guard, the
 *         default). NDEBUG compiles the assert out, so the strict policy does
 *         not, and the unchecked malloc results are reported.
 *
 *         An assert that itself dereferences the pointer is not here: that
 *         dereference is evaluated before the assert establishes anything,
 *         so it is reported under every policy
 *         (fail/testcases_deref_inside_assert_argument.c).
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
