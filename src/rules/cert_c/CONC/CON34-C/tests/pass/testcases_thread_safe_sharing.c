/*
 * Rule: CON34-C
 * Source: testcases
 * Status: PASS - Safe patterns for sharing data with threads
 */

#include <stdlib.h>
#include <threads.h>

int worker(void *arg) {
    int *p = (int *)arg;
    return *p;
}

/* Static storage — safe to share */
void static_to_thread(void) {
    static int x = 42;
    thrd_t t;
    thrd_create(&t, worker, &x);
    thrd_join(t, NULL);
}

/* Heap-allocated — safe to share */
void malloc_to_thread(void) {
    int *x = (int *)malloc(sizeof(int));
    *x = 42;
    thrd_t t;
    thrd_create(&t, worker, x);
    thrd_join(t, NULL);
    free(x);
}

/* NULL argument — safe */
void null_to_thread(void) {
    thrd_t t;
    thrd_create(&t, worker, NULL);
    thrd_join(t, NULL);
}
