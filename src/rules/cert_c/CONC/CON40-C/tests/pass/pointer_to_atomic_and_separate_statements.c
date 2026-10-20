/*
 * Rule: CON40-C
 * Source: testcases
 * Status: PASS - Should not trigger CON40-C violation
 *
 * A pointer to an atomic object is not an atomic object, so comparing the
 * pointer twice reads nothing atomically. Accesses in separate full
 * expressions are separate expressions, and a store of a value that was
 * not computed from the earlier load is not a load-modify-store. Nor is
 * one whose local was given another object's value after the load.
 */

#include <stdatomic.h>
#include <stdbool.h>

static atomic_int counter;
static atomic_bool ready;
static atomic_size_t cached;
static atomic_size_t current;

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

void refresh_cache(void) {
    size_t seen = atomic_load(&cached);
    if (seen == 0) {
        seen = atomic_load(&current);
        atomic_store(&cached, seen);
    }
}
