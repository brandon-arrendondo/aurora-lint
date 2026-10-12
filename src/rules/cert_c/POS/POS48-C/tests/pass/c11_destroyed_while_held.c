/*
 * Rule: POS48-C
 * Source: testcases
 * Status: PASS - Should NOT trigger POS48-C violation
 *
 * The same hazard with a C11 mutex: CON31-C reports it. POS48-C reads the
 * POSIX thread API.
 */

#include <threads.h>

mtx_t lock;

void last_close(void) {
    mtx_lock(&lock);
    mtx_destroy(&lock);
}
