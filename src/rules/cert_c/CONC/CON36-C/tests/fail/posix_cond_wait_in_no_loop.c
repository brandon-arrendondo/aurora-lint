/*
 * Rule: CON36-C
 * Source: thread-API families (POSIX)
 * Status: FAIL - Should trigger CON36-C violation
 *
 * The wait sits in no loop and under no 'if': after a spurious wake-up the
 * function goes on as if the condition held, with nothing re-checking it.
 */

#include <pthread.h>

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ready_cond = PTHREAD_COND_INITIALIZER;
int ready;

void wait_until_ready(void) {
    pthread_mutex_lock(&lock);
    /* VIOLATION: no loop re-checks ready */
    pthread_cond_wait(&ready_cond, &lock);
    pthread_mutex_unlock(&lock);
}
