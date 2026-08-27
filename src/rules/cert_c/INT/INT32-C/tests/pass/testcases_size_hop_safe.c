/*
 * Rule: INT32-C
 * Source: testcases
 * Status: PASS - Should NOT trigger INT32-C violation
 * Description: A size variable computed one statement before malloc()
 * (the one-assignment-hop pattern added for task 604) whose arithmetic
 * provably fits in a 32-bit size_t must stay clean -- the hop
 * resolution must not become a new source of false positives on
 * otherwise-safe code.
 */

#include <stdlib.h>

void safe_constant_hop(void) {
    size_t n = 20;
    size_t sz = n * 4U;
    char *p = malloc(sz);
    if (p == NULL) return;
    free(p);
}
