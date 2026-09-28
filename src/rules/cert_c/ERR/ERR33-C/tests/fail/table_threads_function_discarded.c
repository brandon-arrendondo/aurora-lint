/*
 * Rule: ERR33-C
 * Status: FAIL - mtx_lock() returns thrd_error on failure. Its result is
 * discarded, so the critical section runs whether or not the lock was taken.
 */

#include <threads.h>

static int counter;

void bump(mtx_t *m) {
    mtx_lock(m);
    counter++;
    mtx_unlock(m);
}
