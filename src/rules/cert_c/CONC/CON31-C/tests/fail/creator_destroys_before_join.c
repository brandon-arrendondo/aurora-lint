/*
 * Rule: CON31-C
 * Source: testcases
 * Status: FAIL - Should trigger CON31-C violation
 *
 * The workers lock the mutex, and the function that started them destroys it
 * before it joins them.
 */

#include <threads.h>

mtx_t lock;
int counter;

int worker(void *arg) {
    (void)arg;
    mtx_lock(&lock);
    counter++;
    mtx_unlock(&lock);
    return 0;
}

int run(void) {
    thrd_t workers[4];
    mtx_init(&lock, mtx_plain);
    for (int i = 0; i < 4; i++) {
        thrd_create(&workers[i], worker, NULL);
    }
    /* VIOLATION: the workers may still hold or wait for the lock */
    mtx_destroy(&lock);
    for (int i = 0; i < 4; i++) {
        thrd_join(workers[i], NULL);
    }
    return counter;
}
