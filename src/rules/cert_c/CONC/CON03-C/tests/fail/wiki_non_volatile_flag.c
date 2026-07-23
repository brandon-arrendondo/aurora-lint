/*
 * Rule: CON03-C
 * Source: wiki
 * Status: FAIL - Should trigger CON03-C violation
 *
 * Demonstrates a shared flag variable without volatile qualifier,
 * which can lead to thread synchronization issues.
 */

#include <pthread.h>
#include <unistd.h>

/* Non-compliant: 'done' is shared between threads but not volatile */
static int done = 0;  /* VIOLATION: should be 'volatile int done' */

void *worker_thread(void *arg) {
    while (!done) {
        /* Do some work */
        sleep(1);
    }
    return NULL;
}

void shutdown(void) {
    done = 1;  /* May not be visible to worker_thread without volatile */
}

int main(void) {
    pthread_t thread;
    pthread_create(&thread, NULL, worker_thread, NULL);

    sleep(5);
    shutdown();

    pthread_join(thread, NULL);
    return 0;
}
