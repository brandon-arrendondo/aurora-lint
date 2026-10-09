/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - a portability layer's lock type is still a lock
 */

#include <pthread.h>

#ifdef _WIN32
#  define app_mutex_t CRITICAL_SECTION
#else
#  define app_mutex_t pthread_mutex_t
#endif
typedef app_mutex_t app_lock;

static app_mutex_t state_mutex;
static app_lock log_lock;

void *worker(void *arg) {
    pthread_mutex_lock(&state_mutex);
    pthread_mutex_unlock(&state_mutex);
    pthread_mutex_lock(&log_lock);
    pthread_mutex_unlock(&log_lock);
    return 0;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_join(t, 0);
    return 0;
}
