/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `Dl_info_t` is POSIX's `<dlfcn.h>` type, `char8_t` C23's
 *         `<uchar.h>` type and `constraint_handler_t` Annex K's
 *         `<stdlib.h>` type: none is a project name the scan failed to
 *         read, and none is atomic
 */

#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <uchar.h>

static Dl_info_t last_symbol;
static char8_t last_unit;
static constraint_handler_t previous_handler;

void *worker(void *arg) {
    dladdr(arg, &last_symbol);
    last_unit = 0;
    previous_handler = 0;
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    last_unit = 1;
    previous_handler = 0;
    pthread_join(t, 0);
    return last_unit;
}
