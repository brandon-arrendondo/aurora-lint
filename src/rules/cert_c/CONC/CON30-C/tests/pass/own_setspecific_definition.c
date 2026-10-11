/*
 * Rule: CON30-C
 * Source: thread-API families (POSIX)
 * Status: PASS - Should NOT trigger CON30-C violation
 *
 * The file defines its own pthread_key_create and pthread_setspecific over a
 * fixed table, so its calls reach those bodies, not the POSIX functions. No
 * POSIX key is created or stored into.
 */

#include <stdlib.h>

typedef unsigned pthread_key_t;

static void *slots[8];

int pthread_key_create(pthread_key_t *key, void (*destructor)(void *)) {
    (void)destructor;
    *key = 0;
    return 0;
}

int pthread_setspecific(pthread_key_t key, const void *value) {
    slots[key] = (void *)value;
    return 0;
}

static pthread_key_t key;

void *worker(void *arg) {
    int *data = malloc(sizeof(int));
    pthread_key_create(&key, NULL);
    pthread_setspecific(key, data);
    return arg;
}
