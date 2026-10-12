/*
 * Rule: CON34-C
 * Source: thread-API families (C11)
 * Status: FAIL - Should trigger CON34-C violation
 *
 * Each thread has its own thread_local object; the new thread is handed
 * the creating thread's, whose access from another thread is
 * implementation-defined. It is reported even though main joins the thread
 * before the creating thread could end.
 */

#include <threads.h>
#include <stdio.h>

static thread_local int val;

int child_thread(void *v) {
    printf("Result: %d\n", *(int *)v);
    return 0;
}

int main(void) {
    thrd_t tid;
    val = 1;
    if (thrd_success != thrd_create(&tid, child_thread, &val)) { /* violation */
        return 1;
    }
    thrd_join(tid, NULL);
    return 0;
}
