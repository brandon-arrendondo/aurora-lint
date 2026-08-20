/*
 * Rule: CON03-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON03-C violation
 *
 * Compliant: 'done' is a C11 atomic_bool, so its load/store operations
 * are atomic (the C equivalent of Java's AtomicBoolean).
 */

#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

static atomic_bool done = false;

void *worker_thread(void *arg) {
    while (!atomic_load(&done)) {
        /* Do some work */
        sleep(1);
    }
    return NULL;
}

void shutdown_worker(void) {
    atomic_store(&done, true);
}

int main(void) {
    pthread_t thread;
    pthread_create(&thread, NULL, worker_thread, NULL);

    sleep(5);
    shutdown_worker();

    pthread_join(thread, NULL);
    return 0;
}
