/*
 * Rule: CON37-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON37-C violation
 *
 * The program is multithreaded, but its signal() is its own event-bus
 * function, not the standard one.
 */

#include <pthread.h>

static int pending[8];

static void signal(int event) {
    pending[event & 7] = 1;
}

void *worker(void *arg) {
    (void)arg;
    signal(3);
    return 0;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_join(t, 0);
    return 0;
}
