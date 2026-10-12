/*
 * Rule: CON04-C
 * Source: thread-API families (POSIX)
 * Status: PASS - Should NOT trigger CON04-C violation
 *
 * CERT's compliant shape with POSIX threads: the start routine detaches
 * the thread running it, so the creator need not join it.
 */

#include <pthread.h>
#include <stdio.h>

enum { THREAD_NO = 5 };
static const char mess[] = "This is a test";

void *message_print(void *ptr) {
    if (pthread_detach((pthread_self())) != 0) {
        /* Handle error */
    }
    printf("THREAD: This is the Message %s\n", (const char *)ptr);
    return NULL;
}

int main(void) {
    pthread_t thr[THREAD_NO];
    for (size_t i = 0; i < THREAD_NO; ++i) {
        if (pthread_create(&thr[i], NULL, message_print, (void *)mess) != 0) {
            fprintf(stderr, "Creation of thread %zu failed\n", i);
        }
    }
    return 0;
}
