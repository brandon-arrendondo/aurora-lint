/*
 * Rule: POS48-C
 * Source: testcases
 * Status: PASS - Should NOT trigger POS48-C violation
 *
 * The function destroys the mutex and then writes shared data. No thread
 * that locks the mutex is in view, the function does not hold it, and the
 * write is not a use of the mutex.
 */

#include <pthread.h>

pthread_mutex_t mutex;
int shared_data;

void cleanup_no_wait(void) {
    pthread_mutex_destroy(&mutex);
    shared_data = 0;
}
