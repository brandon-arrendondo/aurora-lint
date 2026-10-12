/*
 * Rule: CON34-C
 * Source: thread-API families (POSIX)
 * Status: FAIL - Should trigger CON34-C violation
 *
 * CERT's noncompliant shape with POSIX threads: the address of a local
 * object is handed to the new thread. The hazard is the same whichever
 * thread API creates the thread.
 */

#include <pthread.h>
#include <stdio.h>

void *child_thread(void *val) {
    int *res = (int *)val;
    printf("Result: %d\n", *res);
    return NULL;
}

void create_thread(pthread_t *tid) {
    int val = 1;
    if (pthread_create(tid, NULL, child_thread, &val) != 0) { /* violation */
        /* Handle error */
    }
}
