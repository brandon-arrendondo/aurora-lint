/*
 * Rule: CON39-C
 * Source: thread-API families (C11)
 * Status: PASS - Should NOT trigger CON39-C violation
 *
 * worker detaches itself, but the joined thread runs worker2, which does
 * not. The start routine is the function the entry argument names, not
 * any function whose name the arguments contain.
 */

#include <threads.h>

int worker(void *arg) {
    thrd_detach(thrd_current());
    return 0;
}

int worker2(void *arg) {
    return 0;
}

void run(void) {
    thrd_t t;
    thrd_create(&t, worker2, NULL);
    thrd_join(t, NULL);
}
