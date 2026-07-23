/*
 * Rule: CON06-C
 * Source: wiki
 * Status: PASS - Data freed before mutex destroyed
 */

#include <stdlib.h>
#include <threads.h>

void good_func(void) {
    mtx_t local_mutex;
    mtx_init(&local_mutex, mtx_plain);
    char *shared_data = malloc(100);
    /* ... use shared_data under mutex ... */
    free(shared_data);
    mtx_destroy(&local_mutex);
}
