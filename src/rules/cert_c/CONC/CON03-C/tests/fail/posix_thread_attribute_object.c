/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `pthread_mutexattr_t` is a `<pthread.h>` object type, not a
 *         project name the scan failed to read, and an attribute object is
 *         no lock
 */

#include <pthread.h>

static pthread_mutexattr_t lock_attr;

void *worker(void *arg) {
    pthread_mutexattr_settype(&lock_attr, PTHREAD_MUTEX_RECURSIVE);
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_mutexattr_init(&lock_attr);
    pthread_join(t, 0);
    return 0;
}
