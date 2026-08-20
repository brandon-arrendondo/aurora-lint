/*
 * Rule: CON03-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON03-C violation
 *
 * Compliant: 'done' is guarded by a mutex on every access, so its
 * read-check-act sequence is atomic (the C equivalent of Java's
 * synchronized accessor methods).
 */

#include <pthread.h>
#include <unistd.h>

static _Atomic int done = 0;
static pthread_mutex_t done_mutex = PTHREAD_MUTEX_INITIALIZER;

static int is_done(void) {
    int result;
    pthread_mutex_lock(&done_mutex);
    result = done;
    pthread_mutex_unlock(&done_mutex);
    return result;
}

void *worker_thread(void *arg) {
    while (!is_done()) {
        /* Do some work */
        sleep(1);
    }
    return NULL;
}

void shutdown_worker(void) {
    pthread_mutex_lock(&done_mutex);
    done = 1;
    pthread_mutex_unlock(&done_mutex);
}

int main(void) {
    pthread_t thread;
    pthread_create(&thread, NULL, worker_thread, NULL);

    sleep(5);
    shutdown_worker();

    pthread_join(thread, NULL);
    return 0;
}
