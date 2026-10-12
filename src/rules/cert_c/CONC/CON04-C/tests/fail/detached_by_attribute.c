/*
 * Rule: CON04-C
 * Source: thread-API families (POSIX)
 * Status: FAIL - Should trigger CON04-C violation
 *
 * The thread is created detached through its attribute object and never
 * joined or detached by call. C11 has no such attribute, and the rule's
 * form does not exempt it, so it is reported.
 */

#include <pthread.h>

void *worker(void *arg) {
    return NULL;
}

void start_detached(void) {
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &attr, worker, NULL); /* violation */
    pthread_attr_destroy(&attr);
}
