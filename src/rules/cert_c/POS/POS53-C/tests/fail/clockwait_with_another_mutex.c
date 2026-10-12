/*
 * Rule: POS53-C
 * Source: thread-API families (POSIX)
 * Status: FAIL - Should trigger POS53-C violation
 *
 * One condition variable is waited on with `m1` through pthread_cond_wait()
 * and with `m2` through pthread_cond_clockwait(). Every wait on a condition
 * variable must use the same mutex.
 */

#include <pthread.h>
#include <time.h>

static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t m1 = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t m2 = PTHREAD_MUTEX_INITIALIZER;
static int ready;

void waiter_a(void) {
    pthread_mutex_lock(&m1);
    while (!ready) {
        pthread_cond_wait(&cv, &m1); /* violation */
    }
    pthread_mutex_unlock(&m1);
}

void waiter_b(const struct timespec *deadline) {
    pthread_mutex_lock(&m2);
    while (!ready) {
        pthread_cond_clockwait(&cv, &m2, CLOCK_MONOTONIC, deadline);
    }
    pthread_mutex_unlock(&m2);
}
