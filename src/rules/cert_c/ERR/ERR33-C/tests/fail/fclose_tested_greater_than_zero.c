/*
 * Rule: ERR33-C
 * Status: FAIL - fclose returns EOF, a negative value, on failure; `r > 0`
 * never sees it.
 */

#include <stdio.h>

int f(FILE *fp) {
    int r = fclose(fp);
    if (r > 0) {
        return 1;
    }
    return 0;
}
