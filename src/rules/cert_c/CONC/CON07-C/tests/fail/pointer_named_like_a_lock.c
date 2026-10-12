/*
 * Rule: CON07-C
 * Source: testcases
 * Status: FAIL - Should trigger CON07-C violation
 *
 * The worker calls through a function pointer that happens to be named
 * mtx_lock. It names an object, not the C11 function (resolved by
 * declaration), so nothing protects the increment.
 */

#include <threads.h>

int shared_counter;

static void noop(void) {}

int worker(void *arg) {
    void (*mtx_lock)(void) = noop;
    (void)arg;
    mtx_lock();
    shared_counter++;
    return 0;
}

int main(void) {
    thrd_t t;
    thrd_create(&t, worker, 0);
    thrd_join(t, 0);
    return 0;
}
