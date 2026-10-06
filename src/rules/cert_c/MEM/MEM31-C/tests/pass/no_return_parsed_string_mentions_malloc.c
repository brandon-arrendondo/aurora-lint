/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * scratch_get() returns through a macro, so its parse holds no `return` and
 * `returns_allocation` falls back to whether the body calls an allocator.
 * It calls none: it hands back a static buffer, and "malloc(" appears only
 * inside the message string it prints. A string is not a call, so the
 * caller owns nothing and has nothing to free.
 */
#include <stdio.h>
#include <stdlib.h>

#define RETURN_PTR(p) return (p)

static char scratch[64];

static char *scratch_get(void) {
    fputs("malloc(64) skipped, using the static scratch buffer\n", stderr);
    RETURN_PTR(scratch);
}

int fill_scratch(char c) {
    char *buf = scratch_get();
    if (buf == NULL) {
        return -1;
    }
    buf[0] = c;
    return buf[0];
}
