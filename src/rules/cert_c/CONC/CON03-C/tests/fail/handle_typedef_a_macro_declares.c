/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `DECLARE_HANDLE(WINDOW);` expands to `typedef HANDLE
 *         WINDOW`, the invocation's own `;` ending it, so `WINDOW` is a
 *         defined type
 */

#include <pthread.h>

typedef void *HANDLE;
#define DECLARE_HANDLE(name) typedef HANDLE name

DECLARE_HANDLE(WINDOW);

static WINDOW main_window;

void *worker(void *arg) {
    main_window = arg;
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    main_window = 0;
    pthread_join(t, 0);
    return main_window != 0;
}
