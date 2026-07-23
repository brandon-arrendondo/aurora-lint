/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - Shared variables without proper synchronization
 */

#include <pthread.h>

/* Case 1: Static int shared flag without volatile or atomic */
static int running = 1;

void *worker(void *arg) {
    while (running) {
        /* work */
    }
    return 0;
}

/* Case 2: Global int shared counter without synchronization */
int global_counter = 0;

void increment(void) {
    global_counter++;
}

/* Case 3: Static pointer shared without volatile */
static char *shared_buffer = 0;

void set_buffer(char *buf) {
    shared_buffer = buf;
}

/* Case 4: Static int used as status flag */
static int error_code = 0;

void report_error(int code) {
    error_code = code;
}
