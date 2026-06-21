// sqc-test: prescan
/*
 * Rule: EXP34-C - Do not dereference null pointers
 * Status: FAIL - Should trigger EXP34-C violation
 * Reason: A precondition assert() establishes non-null, but the pointer is then
 *         reassigned to a nullable value before the dereference, so the assert's
 *         guarantee no longer holds. The precondition-assert suppression
 *         (task 207) must NOT mask this. Also guards the unguarded-malloc FN.
 */

#include <stdlib.h>
#include <assert.h>

struct Mem {
    int flags;
};

void reassign_after_assert(int n) {
    struct Mem *p = malloc(sizeof(struct Mem));
    assert(p != 0);
    p = malloc(sizeof(struct Mem)); /* reassigned to a possibly-null value */
    p->flags = n;                   /* FAIL: assert above no longer applies */
}
