/*
 * Rule: CON30-C
 * Source: thread-API families (POSIX)
 * Status: FAIL - Should trigger CON30-C violation
 *
 * A destructor of (void (*)(void *))0 is a null pointer: no destructor is
 * registered, and the allocation stored under the key is never freed.
 */

#include <pthread.h>
#include <stdlib.h>

static pthread_key_t key;

void init_key(void) {
    pthread_key_create(&key, (void (*)(void *))0);
}

void *worker(void *arg) {
    int *data = malloc(sizeof(int));
    if (data == NULL) {
        return NULL;
    }
    pthread_setspecific(key, data);
    return arg;
}
