/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - the STRICT form of `DECLARE_HANDLE(WINDOW);` expands to
 *         `struct WINDOW__ { int unused; }; typedef struct WINDOW__
 *         *WINDOW`, pasting the struct's tag, so `WINDOW` is a defined type
 */

#include <pthread.h>

#define DECLARE_HANDLE(name) \
    struct name##__ {        \
        int unused;          \
    };                       \
    typedef struct name##__ *name

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
