/*
 * Rule: CON36-C
 * Source: thread-API families (POSIX)
 * Status: FAIL - Should trigger CON36-C violation
 *
 * pthread_cond_timedwait wakes spuriously as well as on a timeout.
 */

#include <pthread.h>
#include <time.h>

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ready_cond = PTHREAD_COND_INITIALIZER;
int ready;

int wait_until_ready(const struct timespec *deadline) {
    int rc = 0;
    pthread_mutex_lock(&lock);
    /* VIOLATION: if doesn't handle spurious wakeups */
    if (!ready) {
        rc = pthread_cond_timedwait(&ready_cond, &lock, deadline);
    }
    pthread_mutex_unlock(&lock);
    return rc;
}
