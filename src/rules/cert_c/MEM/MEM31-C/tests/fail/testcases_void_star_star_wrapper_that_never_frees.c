// sqc-test: prescan
/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * A void** parameter is not itself evidence of a free. record_slot() takes
 * the same shape as a safe-free wrapper and never releases the pointee, so
 * the allocation still leaks. Guards the pointee-free summary against being
 * inferred from the signature rather than the body.
 */

#include <stdlib.h>

static void record_slot(void **slot) {
    (void)slot;
}

void use_buffer(void) {
    char *buf = malloc(32);
    if (!buf) {
        return;
    }
    record_slot((void **)&buf);
}
