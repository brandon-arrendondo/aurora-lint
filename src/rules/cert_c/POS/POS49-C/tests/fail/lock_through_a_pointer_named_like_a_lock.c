/*
 * Rule: POS49-C
 * Source: testcases
 * Status: FAIL - Should trigger POS49-C violation
 *
 * The calls around the writes go through a member and a parameter named
 * like lock wrappers. Neither is a function the project defines, so what
 * they do is not known, and the writes are not read as protected.
 */

#include <pthread.h>

struct flags {
    unsigned int ready : 1;
    unsigned int done : 1;
};

struct ops {
    void (*mutex_lock)(void);
    void (*mutex_unlock)(void);
};

struct flags status;
struct ops *ops;

void *producer(void *arg) {
    (void)arg;
    ops->mutex_lock();
    status.ready = 1;
    ops->mutex_unlock();
    return NULL;
}

void *consumer(void (*app_mutex_lock)(void)) {
    app_mutex_lock();
    status.done = 1;
    return NULL;
}
