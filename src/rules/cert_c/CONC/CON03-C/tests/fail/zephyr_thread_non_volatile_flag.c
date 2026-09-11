/*
 * Rule: CON03-C
 * Source: custom
 * Status: FAIL - should trigger CON03-C violation
 * Description: Zephyr twin of wiki_non_volatile_flag.c: a plain `done`
 * flag polled by a thread spawned with k_thread_create and set from
 * elsewhere, with no synchronization on the flag itself. The `struct
 * k_mutex` declared alongside is a synchronization primitive, not a shared
 * datum, and must not be what gets reported.
 */

#include <zephyr/kernel.h>

static int done = 0;
static struct k_mutex unrelated_lock;

void worker(void *p1, void *p2, void *p3) {
    while (!done) {
        k_sleep(K_MSEC(10));
    }
}

void shutdown(void) {
    done = 1;
}

K_THREAD_STACK_DEFINE(worker_stack, 1024);
struct k_thread worker_data;

int main(void) {
    k_thread_create(&worker_data, worker_stack, K_THREAD_STACK_SIZEOF(worker_stack),
                    worker, NULL, NULL, NULL, 7, 0, K_NO_WAIT);
    shutdown();
    return 0;
}
