/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - in the #else build the bound is 3, so the loop closes three times
 */
#include <stdio.h>

#if defined(A)
#define M 1
#else
#define M 3
#endif

void f(FILE *fp) {
    int k;
    for (k = 0; k < M; k++) {
        fclose(fp);
    }
}
