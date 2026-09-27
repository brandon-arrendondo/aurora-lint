/*
 * Rule: ERR33-C
 * Status: PASS - the fgetc in the for update is tested by the loop
 * condition, which runs next.
 */

#include <stdio.h>

void f(FILE *fp) {
    int c;
    for (c = fgetc(fp); c != EOF; c = fgetc(fp)) {
        putchar(c);
    }
}
