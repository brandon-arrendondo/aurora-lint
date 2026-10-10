/* This file's `slot_t` is an int, whatever another file means by the name. */
#include <pthread.h>

typedef int slot_t;
typedef int handler_t;

static slot_t counter;
static handler_t ticks;

static void *worker(void *arg) {
    counter++;
    ticks++;
    return arg;
}

int start_counter(void) {
    pthread_t t;
    return pthread_create(&t, 0, worker, 0);
}
