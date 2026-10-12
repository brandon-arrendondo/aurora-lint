/*
 * Rule: POS48-C
 * Source: testcases
 * Status: PASS - Should NOT trigger POS48-C violation
 *
 * The reset path initializes the mutex again before locking it, once
 * directly and once through a helper that is handed the mutex.
 */

#include <pthread.h>

struct counter {
    pthread_mutex_t lock;
    long value;
};

void counter_init_lock(pthread_mutex_t *lock);

void counter_reset(struct counter *c) {
    pthread_mutex_destroy(&c->lock);
    pthread_mutex_init(&c->lock, NULL);
    pthread_mutex_lock(&c->lock);
    c->value = 0;
    pthread_mutex_unlock(&c->lock);
}

void counter_reset_by_helper(struct counter *c) {
    pthread_mutex_destroy(&c->lock);
    counter_init_lock(&c->lock);
    pthread_mutex_lock(&c->lock);
    c->value = 0;
    pthread_mutex_unlock(&c->lock);
}
