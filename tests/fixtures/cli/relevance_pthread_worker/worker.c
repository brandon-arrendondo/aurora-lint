#include <pthread.h>

static int shared_flag = 0;

static void *worker(void *arg)
{
    (void)arg;
    shared_flag = 1;
    return 0;
}

int start(void)
{
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_join(t, 0);
    return shared_flag = 0;
}
