/*
 * Rule: CON04-C
 * Source: thread-API families (C11)
 * Status: FAIL - Should trigger CON04-C violation
 *
 * logger detaches itself, but the thread start() creates runs worker,
 * which does not. That thread is never joined or detached; another start
 * routine's self-detach does not release it.
 */

#include <threads.h>

int logger(void *arg) {
    thrd_detach(thrd_current());
    return 0;
}

int worker(void *arg) {
    return 0;
}

void start(void) {
    thrd_t t;
    thrd_create(&t, worker, NULL); /* violation */
}
