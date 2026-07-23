/*
 * Rule: CON01-C
 * Source: testcases
 * Status: FAIL - Should trigger CON01-C violation
 *
 * Mutex unlock without corresponding lock in same function
 */

#include <threads.h>

mtx_t mutex;

void release_only(void) {
    /* VIOLATION: unlocking mutex without acquiring it first */
    mtx_unlock(&mutex);
}
