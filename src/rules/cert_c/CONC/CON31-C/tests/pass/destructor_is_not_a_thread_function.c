/*
 * Rule: CON31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON31-C violation
 *
 * An object's destructor destroys the mutex it owns. No thread creation
 * names the destructor, and it does not hold the mutex.
 */

#include <pthread.h>
#include <stdlib.h>

struct cache {
    pthread_mutex_t lock;
    int *slots;
};

void cache_free(struct cache *c) {
    pthread_mutex_destroy(&c->lock);
    free(c->slots);
    free(c);
}
