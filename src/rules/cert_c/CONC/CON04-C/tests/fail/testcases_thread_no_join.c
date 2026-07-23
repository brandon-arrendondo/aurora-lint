/*
 * Rule: CON04-C
 * Source: testcases
 * Status: FAIL - Should trigger CON04-C violation
 *
 * Thread created without join or detach
 */

#include <threads.h>

int worker(void *arg) {
    return 0;
}

void create_thread_no_join(void) {
    thrd_t thread;
    /* VIOLATION: thread created but never joined or detached */
    thrd_create(&thread, worker, NULL);
}
