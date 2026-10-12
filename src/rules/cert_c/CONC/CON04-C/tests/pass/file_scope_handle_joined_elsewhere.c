/*
 * Rule: CON04-C
 * Source: thread-API families (C11)
 * Status: PASS - Should NOT trigger CON04-C violation
 *
 * The handle is a file-scope object: start() creates the thread and stop()
 * joins it. The handle is identified by its declaration, so the join in
 * another function releases the thread start() created.
 */

#include <threads.h>

static thrd_t background;

static int run(void *arg) {
    return 0;
}

void start(void) {
    thrd_create(&background, run, NULL);
}

void stop(void) {
    thrd_join(background, NULL);
}
