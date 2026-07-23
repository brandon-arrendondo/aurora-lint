/*
 * Rule: CON34-C
 * Source: testcases
 * Status: FAIL - Sharing automatic storage between threads
 */

#include <threads.h>

int worker(void *arg) {
    int *p = (int *)arg;
    return *p;
}

/* Pass address of local to thrd_create */
void local_to_thread(void) {
    int x = 42;
    thrd_t t;
    thrd_create(&t, worker, &x);
    thrd_join(t, NULL);
}

/* Pass address of local array to thrd_create */
void local_array_to_thread(void) {
    int arr[10];
    arr[0] = 1;
    thrd_t t;
    thrd_create(&t, worker, arr);
    thrd_join(t, NULL);
}
