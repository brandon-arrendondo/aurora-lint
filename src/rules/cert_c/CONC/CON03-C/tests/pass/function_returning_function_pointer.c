/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - a function that returns a function pointer is a function,
 * not a shared variable
 */

#include <pthread.h>

static void noop(void) {}
static void (*lookup(const char *name))(void);

void *worker(void *arg) {
    lookup((const char *)arg)();
    return 0;
}

static void (*lookup(const char *name))(void) {
    (void)name;
    return noop;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_join(t, 0);
    return 0;
}
