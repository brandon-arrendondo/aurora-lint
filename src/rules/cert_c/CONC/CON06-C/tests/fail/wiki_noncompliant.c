/*
 * Rule: CON06-C
 * Source: wiki
 * Status: FAIL - Local mutex destroyed before heap data freed
 */

#include <stdlib.h>
#include <threads.h>

void bad_func(void) {
    mtx_t local_mutex;
    mtx_init(&local_mutex, mtx_plain);
    char *shared_data = malloc(100);
    /* ... use shared_data under mutex ... */
    mtx_destroy(&local_mutex);
    /* shared_data still allocated — mutex doesn't outlive data */
    free(shared_data);
}
