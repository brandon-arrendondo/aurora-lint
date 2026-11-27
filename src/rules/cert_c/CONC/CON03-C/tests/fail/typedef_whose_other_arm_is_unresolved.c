/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `chan_t` is `unsigned` unless `USE_HANDLES` is defined,
 *         when it is a `HANDLE` nothing here defines: the file's own `unsigned`
 *         arm is read too, so the type is known to need synchronization
 */

#include <pthread.h>

#if defined(USE_HANDLES)
typedef HANDLE chan_t;
#else
typedef unsigned chan_t;
#endif

static chan_t control_channel;

void *worker(void *arg) {
    control_channel = 1;
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    control_channel = 2;
    pthread_join(t, 0);
    return (int)control_channel;
}
