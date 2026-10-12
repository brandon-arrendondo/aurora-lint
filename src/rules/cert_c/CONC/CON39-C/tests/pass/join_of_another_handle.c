/*
 * Rule: CON39-C
 * Source: thread-API families (C11)
 * Status: PASS - Should NOT trigger CON39-C violation
 *
 * The self-detaching thread is never joined. The function joins another
 * thread, whose start routine does not detach itself.
 */

#include <threads.h>

int fire_and_forget(void *arg) {
    thrd_detach(thrd_current());
    return 0;
}

int compute(void *arg) {
    return 0;
}

void run(void) {
    thrd_t background;
    thrd_t helper;
    thrd_create(&background, fire_and_forget, NULL);
    thrd_create(&helper, compute, NULL);
    thrd_join(helper, NULL);
}
