/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - the type is spelled through a macro cycle, so what it names
 *         is unknown and the rule stays silent rather than guess
 */

#include <pthread.h>

#define SHARED_T OTHER_T
#define OTHER_T SHARED_T

static SHARED_T state;

void *worker(void *arg) {
    state = 0;
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_join(t, 0);
    return 0;
}
