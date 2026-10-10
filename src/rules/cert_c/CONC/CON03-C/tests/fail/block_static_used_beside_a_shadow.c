/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - the block-scope static is used outside the block that
 *         shadows it, so it is shared between the two threads
 */

#include <pthread.h>

void *worker(void *arg) {
    static int s;
    {
        int s = 1;
        s++;
    }
    s++;
    return arg;
}

int main(void) {
    pthread_t t1, t2;
    pthread_create(&t1, 0, worker, 0);
    pthread_create(&t2, 0, worker, 0);
    pthread_join(t1, 0);
    pthread_join(t2, 0);
    return 0;
}
