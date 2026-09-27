/*
 * Rule: ERR33-C
 * Status: PASS - the fgets at the bottom of the body is tested by the
 * while condition before control reaches the use after the loop.
 */

#include <stdio.h>

extern void log_line(const char *);

void f(FILE *fp, char *b, int n) {
    char *l = fgets(b, n, fp);
    while (l != NULL) {
        puts(b);
        l = fgets(b, n, fp);
    }
    log_line(l);
}
