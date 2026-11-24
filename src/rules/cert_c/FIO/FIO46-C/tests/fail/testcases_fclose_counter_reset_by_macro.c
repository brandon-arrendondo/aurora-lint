/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - a macro naming the counter resets it, so the loop passes again
 */
#include <stdio.h>

#define RESET_K k = 0
#define BUMP() (k--)

void object_like(FILE *fp) {
    int k;
    for (k = 0; k < 1; k++) {
        fclose(fp);
        RESET_K;
    }
}

void no_argument(FILE *fp) {
    int k;
    for (k = 0; k < 1; k++) {
        fclose(fp);
        BUMP();
    }
}
