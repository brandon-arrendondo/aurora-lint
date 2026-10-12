/*
 * Rule: CON39-C
 * Source: thread-API families (POSIX)
 * Status: FAIL - Should trigger CON39-C violation
 *
 * CERT's noncompliant shape with POSIX threads: the start routine detaches
 * its own thread, and the creator then joins it.
 */

#include <pthread.h>
#include <stddef.h>

void *thread_func(void *arg) {
    pthread_detach(pthread_self());
    return NULL;
}

int main(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, thread_func, NULL) != 0) { /* violation */
        return 0;
    }
    if (pthread_join(t, NULL) != 0) {
        return 0;
    }
    return 0;
}
