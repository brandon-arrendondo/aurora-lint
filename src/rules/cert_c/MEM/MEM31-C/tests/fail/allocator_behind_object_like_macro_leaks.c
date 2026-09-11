/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: mbedtls's whole allocator story is `#define mbedtls_calloc
 * calloc` in a header. An object-like alias is neither a function-like
 * macro (the expansion engine's territory) nor a constant, so nothing
 * resolved it and `port_calloc(1, 32)` was not an allocation at all -- this
 * leak was invisible, and so were mbedtls's 169 aliased call sites. The
 * callee is classified by the name its alias chain ends at, which makes
 * this a plain `calloc` that is never freed.
 */

#include <stdlib.h>

#define port_calloc calloc

int leaks_through_alias(void) {
    char *p = port_calloc(1, 32);
    if (p == NULL) {
        return -1;
    }
    p[0] = 'x';
    return 0;
}
