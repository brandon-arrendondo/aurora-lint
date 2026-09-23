/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * `bin_clear_free(void *bin, size_t len)` is pointer-first/size-last, the
 * opposite of the `(handle, target)` APIs the last-argument heuristic exists
 * for. Inside the wrapper below the buffer is a LOCAL and the length is the
 * only argument naming a parameter, so the one-resolving-argument rule picks
 * the length -- making `len` a freed parameter of the wrapper and every
 * caller's own length a double free (hostap sae.c, 34 findings, task 1348).
 * The callee's own summary says it releases parameter 0, which contradicts
 * the guess about parameter 1.
 */
#include <stdlib.h>
#include <string.h>

static void bin_clear_free(void *bin, size_t len) {
    if (bin) {
        memset(bin, 0, len);
        free(bin);
    }
}

static void print_bignum(const char *title, size_t prime_len) {
    unsigned char *tmp;

    tmp = malloc(prime_len);
    bin_clear_free(tmp, prime_len);
}

void sswu(size_t prime_len) {
    print_bignum("a", prime_len);
    print_bignum("b", prime_len);
    print_bignum("c", prime_len);
}
