/*
 * Rule: CON01-C
 * Source: thread-API families (POSIX)
 * Status: PASS - Should NOT trigger CON01-C violation
 *
 * One loop locks every worker's mutex and a later loop unlocks them, each
 * loop declaring its own counter `i`. An index is a value, so the two
 * loops' `m[i]` are the same elements: the function releases what it
 * acquired.
 */

#include <pthread.h>

enum { NWORKERS = 8 };
static pthread_mutex_t worker_mutex[NWORKERS];
static int generation;

void advance_all(void) {
    for (int i = 0; i < NWORKERS; i++) {
        pthread_mutex_lock(&worker_mutex[i]);
    }
    generation++;
    for (int i = 0; i < NWORKERS; i++) {
        pthread_mutex_unlock(&worker_mutex[i]);
    }
}
