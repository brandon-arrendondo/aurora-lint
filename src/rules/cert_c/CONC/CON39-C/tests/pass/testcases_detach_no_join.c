/*
 * Rule: CON39-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON39-C violation
 *
 * Thread detached and not joined
 */

#include <threads.h>

int worker(void *arg) {
    thrd_detach(thrd_current());
    return 0;
}

void detach_only(void) {
    thrd_t thread;
    /* COMPLIANT: detached thread is not joined */
    thrd_create(&thread, worker, NULL);
}
