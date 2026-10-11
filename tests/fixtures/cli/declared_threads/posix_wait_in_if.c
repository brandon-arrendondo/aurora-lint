#include <pthread.h>

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ready_cond = PTHREAD_COND_INITIALIZER;
int ready;

void wait_until_ready(void) {
    pthread_mutex_lock(&lock);
    if (!ready) {
        pthread_cond_wait(&ready_cond, &lock);
    }
    pthread_mutex_unlock(&lock);
}
