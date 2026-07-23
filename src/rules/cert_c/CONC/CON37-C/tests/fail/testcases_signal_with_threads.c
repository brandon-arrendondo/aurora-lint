/*
 * Rule: CON37-C
 * Source: testcases
 * Status: FAIL - Should trigger CON37-C violation
 *
 * signal() used in multithreaded program
 */

#include <signal.h>
#include <threads.h>

int worker(void *arg) { return 0; }

void handler(int sig) { /* ... */ }

void setup_handler(void) {
    thrd_t t;
    thrd_create(&t, worker, NULL);
    /* VIOLATION: signal() forbidden in multithreaded program */
    signal(SIGINT, handler);
}
