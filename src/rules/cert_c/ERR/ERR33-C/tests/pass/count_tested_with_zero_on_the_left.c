/*
 * Rule: ERR33-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger ERR33-C violation
 * Description: the fread count is tested with the constant written first; 0 < n is the same test as n > 0.
 */

#include <stdio.h>

void f(FILE *fp, char *b) {
    size_t n = fread(b, 1, 64, fp);
    if (0 < n) {
        b[n - 1] = 0;
    }
}
