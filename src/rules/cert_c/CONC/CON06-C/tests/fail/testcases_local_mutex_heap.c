/*
 * Rule: CON06-C
 * Source: testcases
 * Status: FAIL - Should trigger CON06-C violation
 *
 * Local mutex may not outlive heap-allocated data it protects
 */

#include <threads.h>
#include <stdlib.h>

void local_mutex_with_heap(void) {
    mtx_t mutex;
    mtx_init(&mutex, mtx_plain);
    /* VIOLATION: local mutex may be destroyed while heap data still in use */
    int *data = (int *)malloc(sizeof(int));
    *data = 42;
    mtx_destroy(&mutex);
    free(data);
}
