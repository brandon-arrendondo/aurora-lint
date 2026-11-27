/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `sock_t` is `SOCKET` where `WIN32` is defined, which
 *         nothing here defines, and `int` everywhere else: the `int` arm is
 *         an ordinary object, so the type is known to need synchronization
 */

#include <pthread.h>

#ifdef WIN32
typedef SOCKET sock_t;
#else
typedef int sock_t;
#endif

static sock_t spare_sock;

void *worker(void *arg) {
    spare_sock = 1;
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    spare_sock = 2;
    pthread_join(t, 0);
    return spare_sock;
}
