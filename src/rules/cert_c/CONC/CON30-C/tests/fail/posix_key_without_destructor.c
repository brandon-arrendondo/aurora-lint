/*
 * Rule: CON30-C
 * Source: thread-API families (POSIX)
 * Status: FAIL - Should trigger CON30-C violation
 *
 * The hazard is read API-neutrally: a POSIX key created without a
 * destructor, with heap memory stored under it and never freed, leaks that
 * memory at thread exit exactly as the C11 form does.
 */

#include <pthread.h>
#include <stdlib.h>

static pthread_key_t key;

void init_key(void) {
    /* VIOLATION: no destructor, and nothing frees the stored value */
    pthread_key_create(&key, NULL);
}

void *worker(void *arg) {
    int *data = malloc(sizeof(int));
    if (data == NULL) {
        return NULL;
    }
    *data = 1;
    pthread_setspecific(key, data);
    return arg;
}
