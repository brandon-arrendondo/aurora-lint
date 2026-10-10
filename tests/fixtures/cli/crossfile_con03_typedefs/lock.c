/* Here `slot_t` is a mutex, and `handler_t` a function type. */
#include <pthread.h>

typedef pthread_mutex_t slot_t;
typedef int(handler_t)(void);

static slot_t guard;
static handler_t on_tick;

static void *worker(void *arg) {
    pthread_mutex_lock(&guard);
    on_tick();
    pthread_mutex_unlock(&guard);
    return arg;
}

int start_lock(void) {
    pthread_t t;
    return pthread_create(&t, 0, worker, 0);
}
