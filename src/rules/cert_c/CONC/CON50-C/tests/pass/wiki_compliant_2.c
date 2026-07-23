/*
 * Rule: CON50-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON50-C violation
 */

#include <mutex>
#include <thread>

const size_t maxThreads = 10;

void do_work(size_t i, std::mutex *pm) {
  std::lock_guard<std::mutex> lk(*pm);

  // Access data protected by the lock.
}
/*
 * Rule: CON50-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON50-C violation
 */

#include <pthread.h>

void *thread_func(void *arg) {
    pthread_mutex_t *m = (pthread_mutex_t *)arg;
    pthread_mutex_lock(m);
    /* Access shared data */
    pthread_mutex_unlock(m);
    return NULL;
}

void start_thread(void) {
    pthread_t thread;
    pthread_mutex_t m;  /* Local mutex */

    pthread_mutex_init(&m, NULL);
    pthread_create(&thread, NULL, thread_func, &m);

    /* Join thread before function exits - safe */
    pthread_join(thread, NULL);

    pthread_mutex_destroy(&m);
}
