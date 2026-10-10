/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `sem_t_bytes` is an int whose name begins with "sem_t";
 *         it does not make `counter`, declared with it, a semaphore
 */

#include <pthread.h>

static int counter, sem_t_bytes;

void *worker(void *arg) {
    counter++;
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_join(t, 0);
    return counter;
}
