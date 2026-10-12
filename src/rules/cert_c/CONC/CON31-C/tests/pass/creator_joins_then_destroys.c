/*
 * Rule: CON31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON31-C violation
 *
 * start_thread() starts a thread and joins it before destroying the mutex.
 * It is not a start routine itself: no thread creation names it.
 */

#include <pthread.h>

pthread_mutex_t m;

void *thread_func(void *arg) {
    (void)arg;
    pthread_mutex_lock(&m);
    /* Access shared data */
    pthread_mutex_unlock(&m);
    return NULL;
}

void start_thread(void) {
    pthread_t thread;
    pthread_mutex_init(&m, NULL);
    pthread_create(&thread, NULL, thread_func, NULL);
    pthread_join(thread, NULL);
    pthread_mutex_destroy(&m);
}
