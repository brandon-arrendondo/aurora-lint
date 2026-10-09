/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - a shared static without an initializer is still shared
 */

#include <pthread.h>

/* No initializer: zero-initialized by C's static storage rules, and just as
 * unsynchronized as `static int stop_requested = 0;`. */
static int stop_requested;

void *poller(void *arg) {
    while (!stop_requested) {
        /* work */
    }
    return 0;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, poller, 0);
    stop_requested = 1;
    pthread_join(t, 0);
    return 0;
}
