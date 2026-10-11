#include "os.h"

static os_cond_t cond;
static os_mutex_t lock;
static int ready;

void wait_until_ready(void) {
    os_mutex_lock(&lock);
    if (!ready) {
        os_cond_wait(&cond, &lock);
    }
    os_mutex_unlock(&lock);
}
