/*
 * Rule: POS50-C
 * Source: thread-API families (POSIX)
 * Status: PASS - Should NOT trigger POS50-C violation
 *
 * main hands the parent thread the address of its own pthread_t, which the
 * parent fills in with the child's handle. Handing back a handle this way
 * is CERT's own compliant pattern in its thread-specific storage example,
 * so a thread handle is not reported.
 */

#include <pthread.h>
#include <stddef.h>

void *child(void *arg) {
    return arg;
}

void *parent(void *child_tid) {
    pthread_create((pthread_t *)child_tid, NULL, child, NULL);
    return NULL;
}

int main(void) {
    pthread_t parent_tid, child_tid;
    pthread_create(&parent_tid, NULL, parent, &child_tid);
    pthread_join(parent_tid, NULL);
    pthread_join(child_tid, NULL);
    return 0;
}
