/*
 * Rule: CON36-C
 * Source: thread-API families (POSIX)
 * Status: PASS - Should NOT trigger CON36-C violation
 *
 * A wrapper waits on the condition its caller passes in. The loop that
 * re-checks the condition is the caller's, as here, so the wrapper's own
 * bare wait is not reported.
 */

#include <pthread.h>

struct waiter {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int ready;
};

static void wait_once(struct waiter *w) {
    pthread_cond_wait(&w->cond, &w->lock);
}

static void wait_on(pthread_cond_t *cond, pthread_mutex_t *lock) {
    pthread_cond_wait(cond, lock);
}

void wait_until_ready(struct waiter *w) {
    pthread_mutex_lock(&w->lock);
    while (!w->ready) {
        wait_once(w);
        wait_on(&w->cond, &w->lock);
    }
    pthread_mutex_unlock(&w->lock);
}
