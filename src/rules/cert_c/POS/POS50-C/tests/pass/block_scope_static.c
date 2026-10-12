/*
 * Rule: POS50-C
 * Source: thread-API families (POSIX)
 * Status: PASS - Should NOT trigger POS50-C violation
 *
 * The object is declared inside the function but with static storage
 * duration, so it outlives every thread and is the same object for all of
 * them. Only automatic and thread-local storage are reported.
 */

#include <pthread.h>

void *child_thread(void *val) {
    return val;
}

void create_thread(pthread_t *tid) {
    static int val = 1;
    if (pthread_create(tid, NULL, child_thread, &val) != 0) {
        /* Handle error */
    }
}
