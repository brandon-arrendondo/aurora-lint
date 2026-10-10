/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - the type resolves through the file's own typedef to an
 *         atomic type
 */

#include <pthread.h>
#include <stdatomic.h>

typedef atomic_int hit_count_t;

static hit_count_t hits, misses;

void *worker(void *arg) {
    atomic_fetch_add(&hits, 1);
    atomic_fetch_add(&misses, 1);
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_join(t, 0);
    return 0;
}
