/*
 * Rule: CON50-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON50-C violation
 *
 * Compliant: the local mutex is joined (all waiters guaranteed done)
 * before it is destroyed.
 */

#include <pthread.h>

void *thread_func(void *arg) {
    pthread_mutex_t *m = (pthread_mutex_t *)arg;
    pthread_mutex_lock(m);
    /* Access shared data */
    pthread_mutex_unlock(m);
    return NULL;
}

void start_thread(void) {
    pthread_t thread;
    pthread_mutex_t m;  /* Local mutex */

    pthread_mutex_init(&m, NULL);
    pthread_create(&thread, NULL, thread_func, &m);

    /* Join thread before function exits - safe */
    pthread_join(thread, NULL);

    pthread_mutex_destroy(&m);
}
