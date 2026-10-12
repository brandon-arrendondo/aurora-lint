/*
 * Rule: POS49-C
 * Source: testcases
 * Status: PASS - Should NOT trigger POS49-C violation
 *
 * The writes are made between the project's own lock wrappers, which no
 * thread-API family describes; a wrapper named for the mutex operation it
 * performs counts.
 */

#include <pthread.h>

struct flags {
    unsigned int ready : 1;
    unsigned int done : 1;
};

struct flags status;
pthread_mutex_t status_lock = PTHREAD_MUTEX_INITIALIZER;

void app_mutex_lock(pthread_mutex_t *m);
void app_mutex_unlock(pthread_mutex_t *m);

void *producer(void *arg) {
    (void)arg;
    app_mutex_lock(&status_lock);
    status.ready = 1;
    app_mutex_unlock(&status_lock);
    return NULL;
}

void *consumer(void *arg) {
    (void)arg;
    app_mutex_lock(&status_lock);
    status.done = 1;
    app_mutex_unlock(&status_lock);
    return NULL;
}
