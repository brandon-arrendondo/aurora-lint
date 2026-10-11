#include "shim.h"

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *lock) {
    return os_wait_signalled(cond, lock);
}
