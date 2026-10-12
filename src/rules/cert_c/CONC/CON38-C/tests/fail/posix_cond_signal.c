/*
 * Rule: CON38-C
 * Source: thread-API families (POSIX)
 * Status: FAIL - Should trigger CON38-C violation
 *
 * CERT's noncompliant shape with POSIX threads: every thread waits on one
 * condition variable for its own turn, and a signal wakes only one of
 * them, which may not be the thread whose turn it is.
 */

#include <pthread.h>

enum { NTHREADS = 5 };

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static unsigned long current_step;

void *run_step(void *t) {
    unsigned long my_step = *(unsigned long *)t;
    pthread_mutex_lock(&mutex);
    while (current_step != my_step) {
        pthread_cond_wait(&cond, &mutex);
    }
    current_step++;
    pthread_cond_signal(&cond); /* violation */
    pthread_mutex_unlock(&mutex);
    return NULL;
}
