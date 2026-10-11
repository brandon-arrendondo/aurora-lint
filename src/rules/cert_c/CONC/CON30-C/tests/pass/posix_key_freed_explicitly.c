/*
 * Rule: CON30-C
 * Source: thread-API families (POSIX)
 * Status: PASS - Should NOT trigger CON30-C violation
 *
 * No destructor, but the thread frees the stored value through
 * pthread_getspecific before it ends.
 */

#include <pthread.h>
#include <stdlib.h>

static pthread_key_t key;

void init_key(void) {
    pthread_key_create(&key, NULL);
}

void *worker(void *arg) {
    int *data = malloc(sizeof(int));
    if (data == NULL) {
        return NULL;
    }
    pthread_setspecific(key, data);
    /* ... */
    free(pthread_getspecific(key));
    return arg;
}
