#include <pthread.h>

static pthread_cond_t cond;
static pthread_mutex_t lock;
static int ready;

void wait_until_ready(void) {
    if (!ready) {
        pthread_cond_wait(&cond, &lock);
    }
}
