/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - the thread uses a local that shadows the global
 */

#include <pthread.h>

static int level = 0;

void *worker(void *arg) {
    int level = 3; /* a different object from the file-scope `level` */
    while (level > 0) {
        level--;
    }
    return 0;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_join(t, 0);
    return 0;
}
