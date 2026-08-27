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

/* Establish real concurrent-execution context (task 608): the accessing
 * functions must be reachable from a thread-spawn root for CON07-C's
 * reachability gate to still fire on this fixture. */
void *worker(void *arg) {
    unsafe_increment();
    unsafe_read();
    return 0;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    return 0;
}
