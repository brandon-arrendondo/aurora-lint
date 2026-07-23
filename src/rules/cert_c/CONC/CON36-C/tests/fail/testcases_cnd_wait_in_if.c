/*
 * Rule: CON36-C
 * Source: testcases
 * Status: FAIL - Should trigger CON36-C violation
 *
 * cnd_wait wrapped in if statement (spurious wakeups not handled)
 */

#include <threads.h>

mtx_t mutex;
cnd_t cond;
int ready;

void wait_with_if(void) {
    mtx_lock(&mutex);
    /* VIOLATION: if doesn't handle spurious wakeups */
    if (!ready) {
        cnd_wait(&cond, &mutex);
    }
    mtx_unlock(&mutex);
}
