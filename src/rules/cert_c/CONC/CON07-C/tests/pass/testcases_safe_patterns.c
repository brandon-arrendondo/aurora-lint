/* Rule: CON07-C
 * Source: testcases
 * Status: PASS - Compound operations on shared variables with proper synchronization
 */

#include <threads.h>
#include <stdatomic.h>

/* Case 1: Mutex-protected access to multiple static variables */
static int x;
static int y;
mtx_t xy_mutex;

int get_product(void) {
    mtx_lock(&xy_mutex);
    int result = x * y;
    mtx_unlock(&xy_mutex);
    return result;
}

void set_xy(int nx, int ny) {
    mtx_lock(&xy_mutex);
    x = nx;
    y = ny;
    mtx_unlock(&xy_mutex);
}

/* Case 2: Atomic compound operation */
static atomic_int total;

void accumulate(int value) {
    atomic_fetch_add(&total, value);
}

/* Case 3: Init function accessing static vars (skipped by rule - runs before threading) */
static int config_a;
static int config_b;

void init_config(void) {
    config_a = 10;
    config_b = 20;
}

/* Case 4: Pthread mutex protection */
static int counter;
pthread_mutex_t counter_lock;

void safe_increment(void) {
    pthread_mutex_lock(&counter_lock);
    counter++;
    pthread_mutex_unlock(&counter_lock);
}
