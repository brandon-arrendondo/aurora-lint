/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `u_int32_t` is the C library's BSD `<sys/types.h>` type
 *         and `memory_order` a `<stdatomic.h>` enumeration, neither a project
 *         name the scan failed to read nor itself atomic
 */

#include <pthread.h>
#include <stdatomic.h>
#include <sys/types.h>

static u_int32_t packets;
static memory_order ordering;

void *worker(void *arg) {
    packets++;
    ordering = memory_order_acquire;
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    packets++;
    ordering = memory_order_release;
    pthread_join(t, 0);
    return (int)packets;
}
