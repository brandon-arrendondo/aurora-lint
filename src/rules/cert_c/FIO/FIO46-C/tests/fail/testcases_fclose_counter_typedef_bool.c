/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - a typedef hides _Bool, which k++ leaves at 1, so the loop never ends
 */
#include <stdio.h>

typedef _Bool flag_t;

void f(FILE *fp) {
    flag_t k;
    for (k = 1; k < 2; k++) {
        fclose(fp);
    }
}
