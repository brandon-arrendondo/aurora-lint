/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - a block-scope static without an initializer
 */

#include <pthread.h>

void *worker(void *arg) {
    static int invocations;
    invocations++;
    return 0;
}

int main(void) {
    pthread_t t1, t2;
    pthread_create(&t1, 0, worker, 0);
    pthread_create(&t2, 0, worker, 0);
    pthread_join(t1, 0);
    pthread_join(t2, 0);
    return 0;
}
