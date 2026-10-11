/*
 * Rule: CON30-C
 * Source: thread-API families (POSIX)
 * Status: PASS - Should NOT trigger CON30-C violation
 *
 * The POSIX key is created with free as its destructor.
 */

#include <pthread.h>
#include <stdlib.h>

static pthread_key_t key;

void init_key(void) {
    pthread_key_create(&key, free);
}

void *worker(void *arg) {
    int *data = malloc(sizeof(int));
    if (data == NULL) {
        return NULL;
    }
    pthread_setspecific(key, data);
    return arg;
}
