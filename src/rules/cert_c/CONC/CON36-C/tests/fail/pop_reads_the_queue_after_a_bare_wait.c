/*
 * Rule: CON36-C
 * Source: thread-API families (POSIX)
 * Status: FAIL - Should trigger CON36-C violation
 *
 * The queue comes in as a parameter, but pop is no wrapper: after the wait
 * it reads an item, so a spurious wake-up pops from an empty queue. No loop
 * re-checks that the queue has an item.
 */

#include <pthread.h>

struct q {
    pthread_mutex_t m;
    pthread_cond_t c;
    int items[16];
    int n;
};

int pop(struct q *q) {
    pthread_mutex_lock(&q->m);
    /* VIOLATION: nothing re-checks q->n after waking */
    pthread_cond_wait(&q->c, &q->m);
    int v = q->items[--q->n];
    pthread_mutex_unlock(&q->m);
    return v;
}
