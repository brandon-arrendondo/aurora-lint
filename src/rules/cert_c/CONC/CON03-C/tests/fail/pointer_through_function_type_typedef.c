/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - a pointer declared through a function-type typedef is an
 * object, and a shared one
 */

#include <pthread.h>

typedef void (event_fn)(int code);

static event_fn *on_event;

static void log_event(int code) { (void)code; }

void *worker(void *arg) {
    if (on_event)
        on_event(1);
    return 0;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    on_event = log_event;
    pthread_join(t, 0);
    return 0;
}
