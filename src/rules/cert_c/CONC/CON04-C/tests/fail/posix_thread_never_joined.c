/*
 * Rule: CON04-C
 * Source: thread-API families (POSIX)
 * Status: FAIL - Should trigger CON04-C violation
 *
 * CERT's noncompliant shape with POSIX threads: the threads are created
 * and neither joined nor detached, so their resources are never reclaimed.
 */

#include <pthread.h>
#include <stdio.h>

enum { THREAD_NO = 5 };
static const char mess[] = "This is a test";

void *message_print(void *ptr) {
    printf("THREAD: This is the Message %s\n", (const char *)ptr);
    return NULL;
}

int main(void) {
    pthread_t thr[THREAD_NO];
    for (size_t i = 0; i < THREAD_NO; ++i) {
        if (pthread_create(&thr[i], NULL, message_print, (void *)mess) != 0) { /* violation */
            fprintf(stderr, "Creation of thread %zu failed\n", i);
        }
    }
    return 0;
}
