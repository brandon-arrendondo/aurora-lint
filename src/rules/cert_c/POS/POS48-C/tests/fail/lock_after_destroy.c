/*
 * Rule: POS48-C
 * Source: testcases
 * Status: FAIL - Should trigger POS48-C violation
 *
 * A reset path destroys the mutex and then locks it again without
 * initializing it.
 */

#include <pthread.h>

struct counter {
    pthread_mutex_t lock;
    long value;
};

void counter_reset(struct counter *c) {
    pthread_mutex_destroy(&c->lock);
    /* VIOLATION: the mutex is destroyed */
    pthread_mutex_lock(&c->lock);
    c->value = 0;
    pthread_mutex_unlock(&c->lock);
}
