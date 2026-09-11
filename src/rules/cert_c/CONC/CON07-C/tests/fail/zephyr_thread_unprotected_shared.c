/*
 * Rule: CON07-C
 * Source: custom
 * Status: FAIL - should trigger CON07-C violation
 * Description: Zephyr twin of testcases_unprotected_shared.c. The worker is
 * spawned with k_thread_create (entry at argument 3 of 10), so it is a real
 * concurrent-execution root and the unguarded access to `shared_counter`
 * inside it is reachable from a thread. Before k_thread_create was in the
 * spawn table, no Zephyr thread was ever a root and this rule reported
 * nothing on Zephyr's native idiom.
 */

#include <zephyr/kernel.h>

int shared_counter;
struct k_mutex lock;

void unsafe_increment(void) {
    shared_counter++;
}

void worker(void *p1, void *p2, void *p3) {
    unsafe_increment();
}

K_THREAD_STACK_DEFINE(worker_stack, 1024);
struct k_thread worker_data;

int main(void) {
    k_thread_create(&worker_data, worker_stack, K_THREAD_STACK_SIZEOF(worker_stack),
                    worker, NULL, NULL, NULL, 7, 0, K_NO_WAIT);
    return 0;
}
