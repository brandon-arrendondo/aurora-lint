/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - `regs` is a const pointer: it never changes after its
 *         initializer, so there is nothing to race on, and the device
 *         registers it points at are volatile
 */

#include <pthread.h>

struct device_regs {
    unsigned status;
    unsigned control;
};

static struct device_regs device;
static volatile struct device_regs *const regs = &device;

void *worker(void *arg) {
    while (regs->status == 0) {
        /* wait for the device */
    }
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    regs->control = 1;
    pthread_join(t, 0);
    return 0;
}
