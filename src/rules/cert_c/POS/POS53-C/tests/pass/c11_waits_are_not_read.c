/*
 * Rule: POS53-C
 * Source: thread-API families (C11)
 * Status: PASS - Should NOT trigger POS53-C violation
 *
 * This is POSIX's rule. C11's cnd_wait() carries the one-mutex constraint
 * only by MISRA's reading, so waits through C11 are not read here, even
 * when they use two mutexes on one condition variable.
 */

#include <threads.h>

static cnd_t cv;
static mtx_t m1;
static mtx_t m2;
static int ready;

void waiter_a(void) {
    mtx_lock(&m1);
    while (!ready) {
        cnd_wait(&cv, &m1);
    }
    mtx_unlock(&m1);
}

void waiter_b(void) {
    mtx_lock(&m2);
    while (!ready) {
        cnd_wait(&cv, &m2);
    }
    mtx_unlock(&m2);
}
