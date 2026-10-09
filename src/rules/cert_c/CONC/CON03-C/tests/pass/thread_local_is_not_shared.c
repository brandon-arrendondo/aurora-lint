/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - thread-local storage gives each thread its own object
 */

#include <pthread.h>

static __thread int per_thread_calls;
static _Thread_local char per_thread_buffer[64];

void *worker(void *arg) {
    per_thread_calls++;
    per_thread_buffer[0] = 'x';
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
