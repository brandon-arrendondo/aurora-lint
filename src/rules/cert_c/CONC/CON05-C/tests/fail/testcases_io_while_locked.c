/*
 * Rule: CON05-C
 * Source: testcases
 * Status: FAIL - Should trigger CON05-C violation
 *
 * Blocking I/O while holding a mutex
 */

#include <threads.h>
#include <stdio.h>

mtx_t mutex;

void locked_io(void) {
    mtx_lock(&mutex);
    /* VIOLATION: blocking I/O while holding mutex */
    printf("writing data\n");
    mtx_unlock(&mutex);
}
