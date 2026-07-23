/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - Shared variables with proper synchronization
 */

#include <pthread.h>
#include <stdatomic.h>
#include <signal.h>

/* Case 1: Volatile static flag (correct) */
static volatile int running = 1;

void *worker(void *arg) {
    while (running) {
        /* work */
    }
    return 0;
}

/* Case 2: Atomic shared counter (correct) */
static atomic_int counter = 0;

void increment(void) {
    atomic_fetch_add(&counter, 1);
}

/* Case 3: Const global (read-only, no race) */
static const int max_retries = 5;

int get_max_retries(void) {
    return max_retries;
}

/* Case 4: Synchronization primitive itself (should not be flagged) */
static pthread_mutex_t lock;

void init_lock(void) {
    pthread_mutex_init(&lock, 0);
}
