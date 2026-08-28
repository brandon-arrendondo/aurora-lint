/*
 * Rule: CON07-C
 * Source: task 386 (shadow-awareness regression test)
 * Status: FAIL - a parameter shadowing a shared static's name in one function
 * must not suppress detection of a genuine unprotected compound operation on
 * that static in another function.
 */

#include <pthread.h>

static int counter;

/* `counter` here is a parameter, not the shared static -- must not count as
 * an access to the shared static. */
void uses_shadowing_param(int counter) {
    counter++;
}

/* Genuine unprotected compound operation on the real shared static. */
void unsafe_increment(void) {
    counter++;
}

void *worker(void *arg) {
    uses_shadowing_param(0);
    unsafe_increment();
    return 0;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    return 0;
}
