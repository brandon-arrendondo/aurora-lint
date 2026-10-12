/*
 * Rule: CON38-C
 * Source: thread-API families (C11)
 * Status: PASS - Should NOT trigger CON38-C violation
 *
 * The callee is a function-pointer parameter that happens to be spelled
 * like the C11 signal. A name that resolves to a parameter is that
 * parameter, so the call signals no condition variable.
 */

#include <threads.h>

static cnd_t cond;

void notify_with(int (*cnd_signal)(cnd_t *)) {
    cnd_signal(&cond);
}
