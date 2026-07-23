/*
 * Rule: CON07-C
 * Source: testcases
 * Status: PASS - Shared data accessed with mutex protection
 */

#include <pthread.h>

int shared_counter;
pthread_mutex_t lock;

/* Properly locked access */
void safe_increment(void) {
    pthread_mutex_lock(&lock);
    shared_counter++;
    pthread_mutex_unlock(&lock);
}

/* Local variable — no lock needed */
void local_only(void) {
    int local = 0;
    local++;
    (void)local;
}
