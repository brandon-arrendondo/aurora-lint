/*
 * Rule: POS48-C
 * Source: testcases
 * Status: FAIL - Should trigger POS48-C violation
 *
 * The mutex is destroyed while the destroying function still holds it.
 */

#include <pthread.h>

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
int open_count;

void last_close(void) {
    pthread_mutex_lock(&lock);
    open_count = 0;
    /* VIOLATION: still locked here */
    pthread_mutex_destroy(&lock);
}
