/*
 * Rule: CON01-C
 * Source: thread-API families (POSIX)
 * Status: PASS - Should NOT trigger CON01-C violation
 *
 * The callee is a function-pointer parameter that happens to be spelled
 * like the POSIX unlock. A name that resolves to a parameter is that
 * parameter, so the call performs no mutex operation.
 */

#include <pthread.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void release_through(int (*pthread_mutex_unlock)(pthread_mutex_t *)) {
    pthread_mutex_unlock(&lock);
}
