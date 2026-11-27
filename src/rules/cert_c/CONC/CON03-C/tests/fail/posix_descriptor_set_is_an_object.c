/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `fd_set` is a `<sys/select.h>` object type and
 *         `sigjmp_buf` a `<setjmp.h>` one, not project names the scan failed
 *         to read
 */

#include <pthread.h>
#include <setjmp.h>
#include <sys/select.h>

static fd_set watched;
static sigjmp_buf restart;

void *worker(void *arg) {
    FD_SET(3, &watched);
    siglongjmp(restart, 1);
    return arg;
}

int main(void) {
    pthread_t t;
    FD_ZERO(&watched);
    if (sigsetjmp(restart, 1) == 0) {
        pthread_create(&t, 0, worker, 0);
        pthread_join(t, 0);
    }
    return 0;
}
