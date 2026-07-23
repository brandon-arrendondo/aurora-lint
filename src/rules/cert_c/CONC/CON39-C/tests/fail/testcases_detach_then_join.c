/*
 * Rule: CON39-C
 * Source: testcases
 * Status: FAIL - Should trigger CON39-C violation
 *
 * Thread detached then joined (undefined behavior)
 */

#include <threads.h>

int worker(void *arg) {
    thrd_detach(thrd_current());
    return 0;
}

void detach_and_join(void) {
    thrd_t thread;
    int result;
    thrd_create(&thread, worker, NULL);
    /* VIOLATION: joining a detached thread */
    thrd_join(thread, &result);
}
