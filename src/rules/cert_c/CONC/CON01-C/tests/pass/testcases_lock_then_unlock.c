/*
 * Rule: CON01-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON01-C violation
 *
 * Properly paired mutex lock and unlock
 */

#include <threads.h>

mtx_t mutex;
int shared_data;

void update_data(int value) {
    /* COMPLIANT: lock before unlock */
    mtx_lock(&mutex);
    shared_data = value;
    mtx_unlock(&mutex);
}
