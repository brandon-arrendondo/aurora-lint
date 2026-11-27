/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `OUTER(count_t)` expands to `INNER(count_t)`, which
 *         expands in turn to `typedef int count_t`, so `count_t` is a
 *         defined type, an ordinary object
 */

#include <pthread.h>

#define INNER(n) typedef int n
#define OUTER(n) INNER(n)

OUTER(count_t);

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
    return hits < 100;
}
