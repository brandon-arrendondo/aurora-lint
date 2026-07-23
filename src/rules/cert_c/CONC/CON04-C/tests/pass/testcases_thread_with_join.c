/*
 * Rule: CON04-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON04-C violation
 *
 * Thread created and properly joined
 */

#include <threads.h>

int worker(void *arg) {
    return 0;
}

void create_and_join(void) {
    thrd_t thread;
    int result;
    /* COMPLIANT: thread joined after creation */
    thrd_create(&thread, worker, NULL);
    thrd_join(thread, &result);
}
