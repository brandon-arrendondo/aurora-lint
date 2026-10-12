/*
 * Rule: CON39-C
 * Source: thread-API families (C11)
 * Status: FAIL - Should trigger CON39-C violation
 *
 * The start routine and its creator are defined inside a preprocessor
 * conditional. They are still this file's functions: the self-detached
 * thread is joined.
 */

#include <threads.h>

#ifdef HAVE_THREADS
int thread_func(void *arg) {
    thrd_detach(thrd_current());
    return 0;
}

void run(void) {
    thrd_t t;
    thrd_create(&t, thread_func, NULL); /* violation */
    thrd_join(t, NULL);
}
#endif
