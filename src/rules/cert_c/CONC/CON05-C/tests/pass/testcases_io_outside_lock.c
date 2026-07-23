/*
 * Rule: CON05-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON05-C violation
 *
 * I/O performed outside the locked region
 */

#include <threads.h>
#include <stdio.h>

mtx_t mutex;
int shared_data;

void safe_io(void) {
    int local;
    mtx_lock(&mutex);
    local = shared_data;
    mtx_unlock(&mutex);
    /* COMPLIANT: I/O outside lock */
    printf("data: %d\n", local);
}
