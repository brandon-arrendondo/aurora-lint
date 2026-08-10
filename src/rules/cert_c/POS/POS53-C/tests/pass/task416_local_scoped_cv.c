/*
 * Rule: POS53-C
 * Source: task 416 regression
 * Status: PASS - Should NOT trigger POS53-C violation
 *
 * Two unrelated functions each declare their own function-local condition
 * variable named "cv" and wait on it with their own function-local mutex.
 * Each function individually only ever uses one mutex with its own cv, so
 * this must not be flagged even though the text "cv" repeats across
 * functions and the two mutex names differ.
 */

#include <pthread.h>

void waiter_one(void) {
    pthread_cond_t cv;
    pthread_mutex_t m1;
    pthread_cond_init(&cv, NULL);
    pthread_mutex_init(&m1, NULL);

    pthread_mutex_lock(&m1);
    pthread_cond_wait(&cv, &m1);
    pthread_mutex_unlock(&m1);
}

void waiter_two(void) {
    pthread_cond_t cv;
    pthread_mutex_t m2;
    pthread_cond_init(&cv, NULL);
    pthread_mutex_init(&m2, NULL);

    pthread_mutex_lock(&m2);
    pthread_cond_wait(&cv, &m2);
    pthread_mutex_unlock(&m2);
}
