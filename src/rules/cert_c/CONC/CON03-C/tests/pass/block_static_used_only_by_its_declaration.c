/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - a block-scope static that nothing uses: its own declaration
 *         is not a use, and the inner `s` is a different object
 */

#include <pthread.h>

void *worker(void *arg) {
    static int s;
    {
        int s = 1;
        s++;
    }
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_join(t, 0);
    return 0;
}
