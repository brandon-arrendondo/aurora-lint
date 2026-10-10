/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - the pointer itself is volatile (`int *volatile`), so the
 *         shared object is volatile even though the pointee is not
 */

#include <pthread.h>

static int slots[4];
static int *volatile cursor;

void *worker(void *arg) {
    while (cursor == 0) {
        /* wait for the main thread to publish a slot */
    }
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    cursor = &slots[1];
    pthread_join(t, 0);
    return 0;
}
