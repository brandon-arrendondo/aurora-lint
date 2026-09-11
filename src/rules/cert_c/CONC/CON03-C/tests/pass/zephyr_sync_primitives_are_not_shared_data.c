/*
 * Rule: CON03-C
 * Source: custom
 * Status: PASS - should NOT trigger CON03-C violation
 * Description: Zephyr's synchronization objects are declared as bare
 * structs (`struct k_mutex`, `struct k_spinlock`, `struct k_sem`, `struct
 * k_condvar`), never through a typedef, so a sync-type list written for
 * `pthread_mutex_t`/`mtx_t` did not recognize any of them and reported the
 * locks themselves as unsynchronized shared data. They ARE the
 * synchronization. The flag they protect is atomic, as in wiki_synchronized.c.
 * The spawned worker touches every one of the four objects, so each has an
 * accessor reachable from a concurrent root and only the sync-type list
 * keeps it out of the report.
 * The objects are written in their initialized form (Zephyr's
 * Z_*_INITIALIZER spellings) because the rule only tracks initialized
 * declarations; an uninitialized one would pass vacuously.
 */

#include <zephyr/kernel.h>

static _Atomic int done = 0;
static struct k_mutex done_lock = Z_MUTEX_INITIALIZER(done_lock);
static struct k_spinlock done_spin = {0};
static struct k_sem done_sem = Z_SEM_INITIALIZER(done_sem, 0, 1);
static struct k_condvar done_cv = Z_CONDVAR_INITIALIZER(done_cv);

void worker(void *p1, void *p2, void *p3) {
    k_mutex_lock(&done_lock, K_FOREVER);
    while (!done) {
        k_condvar_wait(&done_cv, &done_lock, K_FOREVER);
    }
    k_mutex_unlock(&done_lock);
    k_spinlock_key_t key = k_spin_lock(&done_spin);
    k_spin_unlock(&done_spin, key);
    k_sem_give(&done_sem);
}

void shutdown(void) {
    k_mutex_lock(&done_lock, K_FOREVER);
    done = 1;
    k_condvar_broadcast(&done_cv);
    k_mutex_unlock(&done_lock);
    k_sem_take(&done_sem, K_FOREVER);
}

K_THREAD_STACK_DEFINE(worker_stack, 1024);
struct k_thread worker_data;

int main(void) {
    k_thread_create(&worker_data, worker_stack, K_THREAD_STACK_SIZEOF(worker_stack),
                    worker, NULL, NULL, NULL, 7, 0, K_NO_WAIT);
    shutdown();
    return 0;
}
