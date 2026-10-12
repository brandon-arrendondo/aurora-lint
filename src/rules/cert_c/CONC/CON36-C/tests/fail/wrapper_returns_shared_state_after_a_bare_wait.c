/*
 * Rule: CON36-C
 * Source: thread-API families (POSIX)
 * Status: FAIL - Should trigger CON36-C violation
 *
 * Each function waits on the condition its caller passes in and then
 * returns state that other threads share: a global, or a static local.
 * Returning it reads what was waited for after a wake-up that may have been
 * spurious, so neither is a wrapper and each bare wait is reported.
 */

#include <pthread.h>

int g_state;

int wait_then_read_global(pthread_cond_t *cond, pthread_mutex_t *lock) {
    pthread_mutex_lock(lock);
    pthread_cond_wait(cond, lock); /* violation */
    pthread_mutex_unlock(lock);
    return g_state;
}

int wait_then_read_static(pthread_cond_t *cond, pthread_mutex_t *lock) {
    static int seen;
    pthread_cond_wait(cond, lock); /* violation */
    return seen;
}
