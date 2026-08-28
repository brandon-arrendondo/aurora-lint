/*
 * Rule: CON07-C
 * Source: task 386 (shadow-awareness regression test)
 * Status: PASS - block-local variables that merely share a name with file-scope
 * statics are not accesses to those statics, and must not be flagged.
 */

#include <pthread.h>

static int a;
static int b;

/* `a` and `b` here are ordinary local variables that happen to share a name
 * with the file-scope statics above. A flat name-based scan would
 * misattribute the compound operation on these locals to the shared
 * statics; a shadow-aware scan must not. */
void local_shadow_no_violation(void) {
    int a = 1;
    int b = 2;
    a = a + b;
    b += a;
}

void *worker(void *arg) {
    local_shadow_no_violation();
    return 0;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    return 0;
}
