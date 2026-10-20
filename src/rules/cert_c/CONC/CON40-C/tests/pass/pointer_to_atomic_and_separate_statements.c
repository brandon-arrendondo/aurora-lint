/*
 * Rule: CON40-C
 * Source: testcases
 * Status: PASS - Should not trigger CON40-C violation
 *
 * A pointer to an atomic object is not an atomic object, so comparing the
 * pointer twice reads nothing atomically. Accesses in separate full
 * expressions are separate expressions, and a store of a value that was
 * not computed from the earlier load is not a load-modify-store.
 */

#include <stdatomic.h>
#include <stdbool.h>

static atomic_int counter;
static atomic_bool ready;

int same_pointer(_Atomic int *p, _Atomic int *q) {
    return p != 0 && p != q;
}

int twice_in_two_statements(void) {
    int a = counter;
    int b = counter;
    return a + b;
}

void publish(void) {
    bool was_ready = atomic_load(&ready);
    atomic_store(&ready, true);
    (void)was_ready;
}
