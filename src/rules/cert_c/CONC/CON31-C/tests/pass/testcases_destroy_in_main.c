/*
 * Rule: CON31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON31-C violation
 *
 * Mutex destroyed in main() after threads complete
 */

#include <threads.h>

mtx_t mutex;

int main(void) {
    thrd_t thread;
    int result;
    mtx_init(&mutex, mtx_plain);
    thrd_create(&thread, NULL, NULL);
    thrd_join(thread, &result);
    /* COMPLIANT: destroy after all threads joined */
    mtx_destroy(&mutex);
    return 0;
}
