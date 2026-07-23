/*
 * Rule: CON07-C
 * Source: testcases
 * Status: FAIL - unprotected compound operation on shared global
 */

#include <pthread.h>

int shared_counter;
pthread_mutex_t lock;

/* Accessing shared data without holding lock */
void unsafe_increment(void) {
    shared_counter++;
}

/* Reading shared data without lock */
int unsafe_read(void) {
    return shared_counter;
}
