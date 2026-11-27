/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `u64` is a typedef this file declares, of `ext_uint64`,
 *         which nothing here defines: the declared type has a definition,
 *         so it is read by its spelling, an ordinary object
 */

#include <pthread.h>

typedef ext_uint64 u64;

static u64 total_bytes;

void *worker(void *arg) {
    total_bytes += 1;
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    total_bytes += 2;
    pthread_join(t, 0);
    return (int)total_bytes;
}
