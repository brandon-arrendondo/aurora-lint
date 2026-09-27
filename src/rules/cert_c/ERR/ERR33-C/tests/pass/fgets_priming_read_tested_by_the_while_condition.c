/*
 * Rule: ERR33-C
 * Status: PASS - the fgets at the bottom of the loop body is tested by the
 * while condition, which runs next.
 */

#include <stdio.h>

void f(FILE *fp, char *b, int n) {
    char *l = fgets(b, n, fp);
    while (l != NULL) {
        puts(b);
        l = fgets(b, n, fp);
    }
}
