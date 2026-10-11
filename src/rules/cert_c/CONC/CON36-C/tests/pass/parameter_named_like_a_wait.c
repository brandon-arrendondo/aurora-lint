/*
 * Rule: CON36-C
 * Source: thread-API families (identity by declaration)
 * Status: PASS - Should NOT trigger CON36-C violation
 *
 * The callee is a parameter, a function pointer that happens to be spelled
 * like the POSIX wait. The occurrence resolves to the parameter, not to the
 * library function, so it is no condition wait (ADR-0006).
 */

#include <pthread.h>

int ready;

void poll_once(int (*pthread_cond_wait)(pthread_cond_t *, pthread_mutex_t *),
               pthread_cond_t *cond, pthread_mutex_t *lock) {
    if (!ready) {
        pthread_cond_wait(cond, lock);
    }
}
