/*
 * Rule: CON06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON06-C violation
 *
 * Static mutex outlives all data it protects
 */

#include <threads.h>
#include <stdlib.h>

static mtx_t mutex;

void static_mutex_safe(void) {
    /* COMPLIANT: static mutex has program lifetime */
    mtx_lock(&mutex);
    int *data = (int *)malloc(sizeof(int));
    *data = 42;
    free(data);
    mtx_unlock(&mutex);
}
