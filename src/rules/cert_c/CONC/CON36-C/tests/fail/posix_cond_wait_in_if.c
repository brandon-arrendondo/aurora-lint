/*
 * Rule: CON36-C
 * Source: thread-API families (POSIX)
 * Status: FAIL - Should trigger CON36-C violation
 *
 * The hazard is read API-neutrally: pthread_cond_wait can wake spuriously
 * exactly as cnd_wait can, so waiting under an 'if' leaves the condition
 * unchecked after a spurious wake-up.
 */

#include <pthread.h>

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ready_cond = PTHREAD_COND_INITIALIZER;
int ready;

void wait_until_ready(void) {
    pthread_mutex_lock(&lock);
    /* VIOLATION: if doesn't handle spurious wakeups */
    if (!ready) {
        pthread_cond_wait(&ready_cond, &lock);
    }
    pthread_mutex_unlock(&lock);
}
