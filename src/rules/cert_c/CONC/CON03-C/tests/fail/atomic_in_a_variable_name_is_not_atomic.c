/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `my_atomic_count` is an int whose name contains "atomic_";
 *         neither it nor `plain`, declared with it, is atomic
 */

#include <pthread.h>

static int my_atomic_count, plain;

void *worker(void *arg) {
    while (!plain) {
        my_atomic_count++;
    }
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    plain = 1;
    pthread_join(t, 0);
    return 0;
}
