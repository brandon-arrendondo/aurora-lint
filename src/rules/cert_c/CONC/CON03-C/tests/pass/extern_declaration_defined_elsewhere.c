/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - an extern declaration defines nothing; the object is
 * reported at its definition, which is in another file
 */

#include <pthread.h>

extern int shared_ticks;

void *worker(void *arg) {
    shared_ticks++;
    return 0;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_join(t, 0);
    return 0;
}
