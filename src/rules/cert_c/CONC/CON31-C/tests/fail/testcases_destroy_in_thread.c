/*
 * Rule: CON31-C
 * Source: testcases
 * Status: FAIL - Should trigger CON31-C violation
 *
 * Mutex destroyed inside thread function
 */

#include <threads.h>

mtx_t mutex;

int thread_func(void *arg) {
    mtx_lock(&mutex);
    /* VIOLATION: destroying mutex in thread function */
    mtx_destroy(&mutex);
    return 0;
}
