/*
 * Rule: CON34-C
 * Source: thread-API families (POSIX)
 * Status: PASS - Should NOT trigger CON34-C violation
 *
 * The argument is the address of a member of the object a pointer points
 * at. That object's storage is the caller's to choose (here, allocated),
 * and nothing in this function names automatic storage.
 */

#include <pthread.h>
#include <stdlib.h>

struct job {
    int input;
    int output;
};

void *run(void *arg) {
    *(int *)arg = 0;
    return NULL;
}

int start(pthread_t *tid, struct job *job) {
    return pthread_create(tid, NULL, run, &job->output);
}
