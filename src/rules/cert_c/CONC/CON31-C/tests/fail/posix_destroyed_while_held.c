/*
 * Rule: CON31-C
 * Source: testcases
 * Status: FAIL - Should trigger CON31-C violation
 *
 * The error path unlocks before it returns, but the main path destroys the
 * mutex while it still holds it.
 */

#include <pthread.h>

struct queue {
    pthread_mutex_t lock;
    int closed;
};

int queue_close(struct queue *q) {
    pthread_mutex_lock(&q->lock);
    if (q->closed) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }
    q->closed = 1;
    /* VIOLATION: still locked here */
    pthread_mutex_destroy(&q->lock);
    return 0;
}
