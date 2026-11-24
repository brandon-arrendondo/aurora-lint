/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - a typedef hides volatile, so the counter may change between passes
 */
#include <stdio.h>

typedef volatile int vint;

void f(FILE *fp) {
    vint k;
    for (k = 0; k < 1; k++) {
        fclose(fp);
    }
}
