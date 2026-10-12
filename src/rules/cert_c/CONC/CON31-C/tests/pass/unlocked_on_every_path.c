/*
 * Rule: CON31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON31-C violation
 *
 * Every path that leaves the lock held either unlocks it or leaves the
 * function before the destroy: a case that unlocks and breaks, and a loop
 * that unlocks and breaks.
 */

#include <threads.h>

mtx_t lock;

int shutdown_by_mode(int mode) {
    mtx_lock(&lock);
    switch (mode) {
    case 0:
        mtx_unlock(&lock);
        break;
    default:
        mtx_unlock(&lock);
        return -1;
    }
    mtx_destroy(&lock);
    return 0;
}

void drain(int *pending) {
    mtx_lock(&lock);
    for (;;) {
        if (*pending == 0) {
            mtx_unlock(&lock);
            break;
        }
        (*pending)--;
    }
    mtx_destroy(&lock);
}
