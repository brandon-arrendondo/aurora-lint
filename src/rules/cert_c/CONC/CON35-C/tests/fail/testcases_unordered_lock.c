/*
 * Rule: CON35-C
 * Source: testcases
 * Status: FAIL - Should trigger CON35-C violation
 *
 * Locking multiple mutexes without predefined order
 */

#include <threads.h>

mtx_t mutex_a;
mtx_t mutex_b;

void unordered_locking(void) {
    /* VIOLATION: no ordering guarantee on multiple lock acquisitions */
    mtx_lock(&mutex_a);
    mtx_lock(&mutex_b);
    mtx_unlock(&mutex_b);
    mtx_unlock(&mutex_a);
}
