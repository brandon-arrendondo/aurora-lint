/*
 * Rule: CON35-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON35-C violation
 *
 * Ordered locking with id comparison determines lock order
 */

#include <threads.h>

void ordered_locking(mtx_t *m1, mtx_t *m2, int id1, int id2) {
    mtx_t *first;
    mtx_t *second;

    /* COMPLIANT: predefined ordering by comparing IDs */
    if (id1 < id2) {
        first = m1;
        second = m2;
    } else {
        first = m2;
        second = m1;
    }
    mtx_lock(first);
    mtx_lock(second);
    mtx_unlock(second);
    mtx_unlock(first);
}
