/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - the body steps the counter back, so the loop passes again
 */
#include <stdio.h>

void f(FILE *fp) {
    int k;
    for (k = 0; k < 1; k++) {
        fclose(fp);
        k--;
    }
}
