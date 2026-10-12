/*
 * Rule: POS53-C
 * Source: thread-API families (POSIX)
 * Status: PASS - Should NOT trigger POS53-C violation
 *
 * Both waits use one mutex, written `&m1` in one and `&(m1)` in the other.
 * The mutex is identified by its declaration, not by how the argument is
 * spelled.
 */

#include <pthread.h>

static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t m1 = PTHREAD_MUTEX_INITIALIZER;
static int ready;

void waiter_a(void) {
    pthread_mutex_lock(&m1);
    while (!ready) {
        pthread_cond_wait(&cv, &m1);
    }
    pthread_mutex_unlock(&m1);
}

void waiter_b(void) {
    pthread_mutex_lock(&(m1));
    while (!ready) {
        pthread_cond_wait(&cv, &(m1));
    }
    pthread_mutex_unlock(&(m1));
}
