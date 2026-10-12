/*
 * Rule: POS49-C
 * Source: testcases
 * Status: FAIL - Should trigger POS49-C violation
 *
 * The comments around the writes name pthread_mutex_lock and
 * pthread_mutex_unlock, but no lock is taken: only calls count.
 */

#include <pthread.h>

struct flags {
    unsigned int ready : 1;
    unsigned int done : 1;
};

struct flags status;

void *producer(void *arg) {
    (void)arg;
    /* TODO: take pthread_mutex_lock(&status_lock) here */
    status.ready = 1;
    /* ...and pthread_mutex_unlock(&status_lock) here */
    return NULL;
}

void *consumer(void *arg) {
    (void)arg;
    status.done = 1;
    return NULL;
}
