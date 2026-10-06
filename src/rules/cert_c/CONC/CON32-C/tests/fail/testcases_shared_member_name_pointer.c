/*
 * Rule: CON32-C
 * Description: Two bit-field structs share a member name; the access through a pointer parameter is reported against its pointee struct
 * Status: FAIL - Should trigger CON32-C violation
 */

#include <threads.h>

struct beta_bits {
    unsigned int armed : 1;
    unsigned int fired : 1;
};

struct omega_bits {
    unsigned int armed : 1;
    unsigned int cleared : 1;
};

int watcher(void *arg) {
    struct omega_bits *bits = arg;
    bits->armed = 0;
    return 0;
}
