/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `pthread_condattr_t` is a `<pthread.h>` object type, not a
 *         project name the scan failed to read, and an attribute object is
 *         no lock
 */

#include <pthread.h>

static pthread_condattr_t cond_attr;

void *worker(void *arg) {
    pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_PRIVATE);
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_condattr_init(&cond_attr);
    pthread_join(t, 0);
    return 0;
}
