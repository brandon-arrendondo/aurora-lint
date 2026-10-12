/*
 * Rule: CON04-C
 * Source: thread-API families (C11)
 * Status: PASS - Should NOT trigger CON04-C violation
 *
 * The handles are stored into an array by one loop and joined by another,
 * through a different index variable. Whether every thread is joined is a
 * question about the whole array, so the join loop releases them.
 */

#include <threads.h>

enum { NTHREADS = 4 };

static int work(void *arg) {
    return 0;
}

void run_all(void) {
    thrd_t threads[NTHREADS];
    for (int i = 0; i < NTHREADS; i++) {
        thrd_create(&threads[i], work, NULL);
    }
    for (int j = 0; j < NTHREADS; j++) {
        thrd_join(threads[j], NULL);
    }
}
