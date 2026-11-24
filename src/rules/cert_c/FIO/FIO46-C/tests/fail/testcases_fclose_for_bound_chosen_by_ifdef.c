/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - in the WIDE build the bound is 4, so the loop closes again
 */
#include <stdio.h>

void f(FILE *fp)
{
    int k;
    for (k = 0; k <
#ifdef WIDE
         4
#else
         1
#endif
         ; k++) {
        fclose(fp);
    }
}
