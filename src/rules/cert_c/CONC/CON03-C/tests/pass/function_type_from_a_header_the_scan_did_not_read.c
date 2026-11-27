/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - `event_cb` comes from a header the scan did not read; if it
 *         names a function type, `static event_cb on_event;` declares a
 *         function, not a shared object
 */

#include <pthread.h>
#include "events.h"

static event_cb on_event;

void *worker(void *arg) {
    on_event(arg);
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    on_event(0);
    pthread_join(t, 0);
    return 0;
}
