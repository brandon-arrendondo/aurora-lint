/*
 * Rule: POS53-C
 * Source: thread-API families (POSIX)
 * Status: PASS - Should NOT trigger POS53-C violation
 *
 * One function waits on the file-scope condition variable `cv` with `m1`.
 * Another declares its own `cv` and `m2`, shadowing the global, and waits
 * on those. They are two condition variables, each used with one mutex.
 */

#include <pthread.h>

static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t m1 = PTHREAD_MUTEX_INITIALIZER;
static int ready;

void wait_shared(void) {
    pthread_mutex_lock(&m1);
    while (!ready) {
        pthread_cond_wait(&cv, &m1);
    }
    pthread_mutex_unlock(&m1);
}

void wait_private(void) {
    pthread_cond_t cv;
    pthread_mutex_t m2;
    pthread_cond_init(&cv, NULL);
    pthread_mutex_init(&m2, NULL);
    pthread_mutex_lock(&m2);
    while (!ready) {
        pthread_cond_wait(&cv, &m2);
    }
    pthread_mutex_unlock(&m2);
}
