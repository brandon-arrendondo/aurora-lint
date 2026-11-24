/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - the macro names another macro that resets the counter, so the loop passes again
 */
#include <stdio.h>

#define RST_INNER k = 0
#define RST() RST_INNER

void f(FILE *fp)
{
    int k;
    for (k = 0; k < 1; k++) {
        fclose(fp);
        RST();
    }
}
