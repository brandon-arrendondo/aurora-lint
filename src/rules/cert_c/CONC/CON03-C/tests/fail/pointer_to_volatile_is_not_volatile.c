/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `volatile int *cursor` points at volatile data, but the
 *         pointer that both threads read and write is not volatile
 */

#include <pthread.h>

static volatile int slots[4];
static volatile int *cursor;

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
