/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - in the WIDE build the loop closes four times; the headers share one body
 */
#include <stdio.h>

void f(FILE *fp)
{
    int k;
#ifdef WIDE
    for (k = 0; k < 4; k++)
#else
    for (k = 0; k < 1; k++)
#endif
    {
        fclose(fp);
    }
}
