/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - -1 converts to UINT_MAX, so the loop runs and closes again
 */
#include <stdio.h>

#define NEG (-1)

void literal(FILE *fp) {
    unsigned k;
    for (k = 0; k < -1; k++) {
        fclose(fp);
    }
}

void named(FILE *fp) {
    unsigned k;
    for (k = 0; k < NEG; k++) {
        fclose(fp);
    }
}
