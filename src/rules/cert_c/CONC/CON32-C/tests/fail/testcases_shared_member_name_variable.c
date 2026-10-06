/*
 * Rule: CON32-C
 * Description: Two bit-field structs share the member name ready; the access is reported against the variable's own struct
 * Status: FAIL - Should trigger CON32-C violation
 */

#include <threads.h>

struct alpha_flags {
    unsigned int ready : 1;
    unsigned int busy : 1;
};

struct zeta_flags {
    unsigned int ready : 1;
    unsigned int done : 1;
};

struct zeta_flags worker_state;

int worker(void *arg) {
    (void)arg;
    worker_state.ready = 1;
    return 0;
}
