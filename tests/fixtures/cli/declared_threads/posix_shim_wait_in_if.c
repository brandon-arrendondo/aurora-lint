#include "shim.h"

static int ready;

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *lock) {
    return os_wait_signalled(cond, lock);
}

void wait_until_ready(pthread_cond_t *cond, pthread_mutex_t *lock) {
    if (!ready) {
        pthread_cond_wait(cond, lock);
    }
}
