/*
 * Rule: CON36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON36-C violation
 *
 * cnd_wait properly wrapped in while loop
 */

#include <threads.h>

mtx_t mutex;
cnd_t cond;
int ready;

void wait_with_while(void) {
    mtx_lock(&mutex);
    /* COMPLIANT: while loop handles spurious wakeups */
    while (!ready) {
        cnd_wait(&cond, &mutex);
    }
    mtx_unlock(&mutex);
}
