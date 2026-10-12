/*
 * Rule: CON05-C
 * Source: testcases
 * Status: FAIL - Should trigger CON05-C violation
 *
 * The thread sleeps while it holds the mutex.
 */

#include <threads.h>

mtx_t lock;

void backoff(const struct timespec *delay) {
    mtx_lock(&lock);
    /* VIOLATION: every other thread waits out the sleep too */
    thrd_sleep(delay, NULL);
    mtx_unlock(&lock);
}
