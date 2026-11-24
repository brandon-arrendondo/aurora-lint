/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - an asm output writes the counter, so the loop may pass again
 */
#include <stdio.h>

void f(FILE *fp) {
    int k;
    for (k = 0; k < 1; k++) {
        fclose(fp);
        __asm__ volatile("" : "=r"(k));
    }
}
