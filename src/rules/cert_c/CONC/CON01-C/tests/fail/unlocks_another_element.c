/*
 * Rule: CON01-C
 * Source: thread-API families (POSIX)
 * Status: FAIL - Should trigger CON01-C violation
 *
 * One branch locks the mutex at index `last`; the other unlocks the
 * mutexes at indices `i`, which the function never locked. An array
 * element is identified by its index as well as its array, so locking one
 * element does not acquire the others.
 */

#include <pthread.h>

enum { NWORKERS = 8 };
static pthread_mutex_t worker_mutex[NWORKERS];

void scale(int active, int target) {
    if (target > active) {
        for (int i = active; i < target; i++) {
            pthread_mutex_unlock(&worker_mutex[i]); /* violation */
        }
    } else if (target < active) {
        int last = active - 1;
        pthread_mutex_lock(&worker_mutex[last]);
    }
}
