/*
 * Rule: CON07-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON07-C violation
 *
 * The increment is made under a timed lock. Lock calls are read by their
 * thread-API contract, so every POSIX lock form counts, not only
 * pthread_mutex_lock().
 */

#include <pthread.h>
#include <time.h>

int shared_counter;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *worker(void *arg) {
    const struct timespec *deadline = arg;
    if (pthread_mutex_timedlock(&lock, deadline) == 0) {
        shared_counter++;
        pthread_mutex_unlock(&lock);
    }
    return 0;
}

int main(void) {
    pthread_t t;
    struct timespec deadline = {0, 0};
    pthread_create(&t, 0, worker, &deadline);
    pthread_join(t, 0);
    return 0;
}
