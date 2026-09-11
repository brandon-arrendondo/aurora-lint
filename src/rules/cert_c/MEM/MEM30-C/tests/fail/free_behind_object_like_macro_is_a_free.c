/*
 * Rule: MEM30-C
 * Source: custom
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: `#define discard free` is the object-like alias shape
 * mbedtls uses for its allocator (`#define mbedtls_free free`). mbedtls's
 * spelling happened to contain FREE and so was caught by the name guess;
 * this one does not, and a callee dispatched on its spelling is an unknown
 * function whose argument is merely checked, not released. Dispatching on
 * the name the alias chain ends at makes this the literal `free` it is, and
 * the write that follows a use after free.
 */

#include <stdlib.h>

#define discard free

void use_after_aliased_free(void) {
    char *p = malloc(16);
    if (p == NULL) {
        return;
    }
    discard(p);
    p[0] = 'x';
}
