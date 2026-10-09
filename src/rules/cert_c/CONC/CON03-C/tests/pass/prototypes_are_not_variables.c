/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - function prototypes declare no shared object
 */

#include <pthread.h>

static void drain(void);
int refill(int amount), *slot_for(int index);

void *worker(void *arg) {
    drain();
    refill(1);
    return slot_for(0);
}

static void drain(void) {}
int refill(int amount) { return amount; }
int *slot_for(int index) { (void)index; return 0; }

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_join(t, 0);
    return 0;
}
