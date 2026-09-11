/*
 * Rule: CON07-C
 * Source: custom
 * Status: PASS - should NOT trigger CON07-C violation
 * Description: Zephyr twin of testcases_protected_shared.c. Every access to
 * `shared_counter` from the k_thread_create'd worker is under a Zephyr
 * lock -- k_mutex_lock/k_mutex_unlock, k_spin_lock/k_spin_unlock, or the
 * irq_lock/irq_unlock critical section older Zephyr code uses -- so this is
 * the protected shape the rule must recognize as such.
 */

#include <zephyr/kernel.h>

int shared_counter;
struct k_mutex lock;
struct k_spinlock spin;

void mutex_increment(void) {
    k_mutex_lock(&lock, K_FOREVER);
    shared_counter++;
    k_mutex_unlock(&lock);
}

void spin_increment(void) {
    k_spinlock_key_t key = k_spin_lock(&spin);
    shared_counter++;
    k_spin_unlock(&spin, key);
}

void irq_increment(void) {
    unsigned int key = irq_lock();
    shared_counter++;
    irq_unlock(key);
}

void worker(void *p1, void *p2, void *p3) {
    mutex_increment();
    spin_increment();
    irq_increment();
}

K_THREAD_STACK_DEFINE(worker_stack, 1024);
struct k_thread worker_data;

int main(void) {
    k_thread_create(&worker_data, worker_stack, K_THREAD_STACK_SIZEOF(worker_stack),
                    worker, NULL, NULL, NULL, 7, 0, K_NO_WAIT);
    return 0;
}
