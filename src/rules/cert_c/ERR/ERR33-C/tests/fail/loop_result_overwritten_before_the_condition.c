/*
 * Rule: ERR33-C
 * Status: FAIL - the fgets result in the loop body is overwritten before
 * the while condition runs, so the condition never sees it.
 */

#include <stdio.h>

void f(FILE *fp, char *b, int n) {
    char *l = fgets(b, n, fp);
    while (l != NULL) {
        l = fgets(b, n, fp);
        l = b;
    }
}
