/*
 * Rule: CON03-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON03-C violation
 *
 * Compliant: 'done' is a simple shared flag (not a compound operation),
 * so a volatile qualifier alone is sufficient to make writer/reader
 * visibility reliable.
 */

#include <pthread.h>
#include <unistd.h>

static volatile int done = 0;

void *worker_thread(void *arg) {
    while (!done) {
        /* Do some work */
        sleep(1);
    }
    return NULL;
}

void shutdown_worker(void) {
    done = 1;
}

int main(void) {
    pthread_t thread;
    pthread_create(&thread, NULL, worker_thread, NULL);

    sleep(5);
    shutdown_worker();

    pthread_join(thread, NULL);
    return 0;
}
