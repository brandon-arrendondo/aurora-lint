/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `DECLARE_T(count_t)` expands to `typedef int count_t;`, so
 *         `count_t` is a defined type, an ordinary object, not a name the
 *         scan failed to read
 */

#include <pthread.h>

#define DECLARE_T(n) typedef int n;

DECLARE_T(count_t)
#define HITS_LIMIT 100

static count_t hits;

void *worker(void *arg) {
    hits++;
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    hits++;
    pthread_join(t, 0);
    return hits < HITS_LIMIT;
}
