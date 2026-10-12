/*
 * Rule: CON31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON31-C violation
 *
 * The only thread that locks the mutex destroys it once it is done with it;
 * no other thread may be using it then.
 */

#include <threads.h>

mtx_t lock;

int worker(void *arg) {
    (void)arg;
    mtx_lock(&lock);
    /* work */
    mtx_unlock(&lock);
    mtx_destroy(&lock);
    return 0;
}

int main(void) {
    thrd_t t;
    mtx_init(&lock, mtx_plain);
    thrd_create(&t, worker, NULL);
    thrd_join(t, NULL);
    return 0;
}
