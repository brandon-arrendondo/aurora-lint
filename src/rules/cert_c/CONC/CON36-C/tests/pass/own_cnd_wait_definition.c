/*
 * Rule: CON36-C
 * Source: thread-API families (C11)
 * Status: PASS - Should NOT trigger CON36-C violation
 *
 * The file defines its own cnd_wait, a wait that never wakes without a
 * signal. Its calls reach that body, not the C11 function, so waiting under
 * an 'if' is not the spurious wake-up hazard.
 */

typedef struct { int signalled; } cnd_t;
typedef struct { int held; } mtx_t;

static int cnd_wait(cnd_t *cond, mtx_t *mtx) {
    (void)mtx;
    while (!cond->signalled) {
    }
    cond->signalled = 0;
    return 0;
}

static cnd_t cond;
static mtx_t lock;
static int ready;

void wait_until_ready(void) {
    if (!ready) {
        cnd_wait(&cond, &lock);
    }
}
