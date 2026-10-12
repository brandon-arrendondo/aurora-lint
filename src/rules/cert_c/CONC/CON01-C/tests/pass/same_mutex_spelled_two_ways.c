/*
 * Rule: CON01-C
 * Source: thread-API families (POSIX)
 * Status: PASS - Should NOT trigger CON01-C violation
 *
 * The function locks and unlocks one mutex, spelled `&lock` once and
 * `&(lock)` once. The mutex is identified by its declaration, not by how
 * the argument is written, so the unlock releases what this function
 * acquired.
 */

#include <pthread.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int counter;

void increment(void) {
    pthread_mutex_lock(&lock);
    counter++;
    pthread_mutex_unlock(&(lock));
}
