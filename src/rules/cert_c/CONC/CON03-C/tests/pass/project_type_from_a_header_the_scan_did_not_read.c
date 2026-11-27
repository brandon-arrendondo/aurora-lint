/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - nothing the scan read defines `conn_pool_t`: its header is
 *         missing, so the type may be a lock or a function type, and its
 *         name is no evidence either way
 */

#include <pthread.h>
#include "pool.h"

static conn_pool_t pool;

void *worker(void *arg) {
    pool_acquire(&pool);
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pool_acquire(&pool);
    pthread_join(t, 0);
    return 0;
}
