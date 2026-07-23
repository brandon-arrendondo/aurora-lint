/*
 * Rule: CON50-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON50-C violation
 */

#include <pthread.h>

void *thread_func(void *arg) {
    pthread_mutex_t *m = (pthread_mutex_t *)arg;
    pthread_mutex_lock(m);
    /* Access shared data */
    pthread_mutex_unlock(m);
    return NULL;
}

pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;  /* Global mutex - safe */

void start_thread(void) {
    pthread_t thread;
    pthread_create(&thread, NULL, thread_func, &m);
}
