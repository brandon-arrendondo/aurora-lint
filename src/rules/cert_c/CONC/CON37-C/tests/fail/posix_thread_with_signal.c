/*
 * Rule: CON37-C
 * Source: testcases
 * Status: FAIL - Should trigger CON37-C violation
 *
 * The file creates a thread through POSIX, read by its thread-API contract,
 * and installs a handler with the standard signal().
 */

#include <pthread.h>
#include <signal.h>

static volatile sig_atomic_t stop;

static void on_term(int sig) { (void)sig; stop = 1; }

static void *poller(void *arg) {
    (void)arg;
    while (!stop) {
    }
    return 0;
}

int main(void) {
    pthread_t t;
    /* VIOLATION: signal() in a multithreaded program */
    signal(SIGTERM, on_term);
    pthread_create(&t, 0, poller, 0);
    pthread_join(t, 0);
    return 0;
}
