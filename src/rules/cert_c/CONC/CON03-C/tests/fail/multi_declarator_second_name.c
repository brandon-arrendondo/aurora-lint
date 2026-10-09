/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - every declarator of a multi-declarator line is collected
 */

#include <pthread.h>

/* Only `pending_events` is touched, and only the second declarator: the
 * finding must come from it. */
static int unused_slot = 0, pending_events;

void *consumer(void *arg) {
    while (pending_events == 0) {
        /* wait */
    }
    return 0;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, consumer, 0);
    pending_events = 1;
    pthread_join(t, 0);
    return 0;
}
