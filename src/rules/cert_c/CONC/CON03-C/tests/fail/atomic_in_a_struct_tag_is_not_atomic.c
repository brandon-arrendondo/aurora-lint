/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `struct atomic_stats` is an ordinary struct: C reserves the
 *         `atomic_` prefix for type names, and a tag spelled that way names
 *         no atomic type
 */

#include <pthread.h>

struct atomic_stats {
    int hits;
};

static struct atomic_stats stats;

void *worker(void *arg) {
    stats.hits++;
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_join(t, 0);
    return stats.hits;
}
