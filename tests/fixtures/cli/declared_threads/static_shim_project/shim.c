#include <pthread.h>

static int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *lock) {
    (void)cond;
    (void)lock;
    return 0;
}

int local_wait(pthread_cond_t *cond, pthread_mutex_t *lock) {
    return pthread_cond_wait(cond, lock);
}
