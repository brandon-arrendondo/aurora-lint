/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - a block-scope static declared in either arm of an #if is
 * one object, used whichever arm's declaration a use resolves to
 */

#include <pthread.h>

void *worker(void *arg) {
#ifdef USE_LARGE_TABLE
    static int slots = 64;
#else
    static int slots = 8;
#endif
    slots--;
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
