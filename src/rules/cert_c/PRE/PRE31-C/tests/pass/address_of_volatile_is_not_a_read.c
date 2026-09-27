/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: taking the address of a volatile object or member reads nothing.
 */

#include <assert.h>

struct m { volatile int nRef; };
volatile int flag;
static int ok(const volatile int *p) { return p != 0; }

void f(struct m *p) {
    assert(ok(&p->nRef));
    assert(ok(&flag));
}
