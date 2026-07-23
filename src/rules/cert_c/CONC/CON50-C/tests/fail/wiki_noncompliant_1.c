/*
 * Rule: CON50-C
 * Source: wiki
 * Status: FAIL - Should trigger CON50-C violation
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
    pthread_mutex_t m;  /* Local mutex - destroyed when function exits */

    pthread_mutex_init(&m, NULL);
    pthread_create(&thread, NULL, thread_func, &m);

    /* Missing pthread_join - thread may still be using m when it's destroyed */
}
