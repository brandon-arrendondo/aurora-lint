/*
 * Rule: MEM31-C
 * Source: real-world regression (pure-ftpd's ftpd.h spelling)
 * Status: FAIL under every preset
 *
 * __attribute__((noreturn)) is a promise the compiler does not check, so it
 * is proof under neither policy (ADR-0015): with no body in view verified
 * never to return, the free() before each call can reach the free() after
 * the `if`. Both the trailing and the leading spelling.
 */

#include <stdlib.h>

static void die_trailing(const char *msg) __attribute__((noreturn));
static __attribute__((noreturn)) void die_leading(const char *msg);

void trailing_attribute(int cond) {
    char *p = malloc(32);
    if (cond) {
        free(p);
        die_trailing("out of memory");
    }
    free(p);
}

void leading_attribute(int cond) {
    char *p = malloc(32);
    if (cond) {
        free(p);
        die_leading("out of memory");
    }
    free(p);
}
