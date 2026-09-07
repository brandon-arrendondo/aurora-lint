/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM30-C violation
 *
 * release_slot() unconditionally forwards its parameter to backend_free()
 * through a cast, so buf is freed on every path through the call and the
 * following write is a use-after-free. The passthrough edge only exists if
 * the cast is stripped (task 1034, tools_sqc).
 */

#include <stdlib.h>

static void backend_free(unsigned char *raw) {
    free(raw);
}

static void release_slot(void *p) {
    backend_free((unsigned char *)p);
}

void use_buffer(void) {
    char *buf = malloc(32);
    if (!buf) {
        return;
    }
    release_slot(buf);
    buf[0] = 'x';
}
