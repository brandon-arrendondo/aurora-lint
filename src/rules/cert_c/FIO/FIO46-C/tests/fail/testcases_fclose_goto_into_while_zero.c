/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - the goto enters the while (0) body a second time after it closed
 */
#include <stdio.h>

void f(FILE *fp, int again) {
    goto in;
    while (0) {
    in:
        fclose(fp);
    }
    if (again) {
        goto in;
    }
}
