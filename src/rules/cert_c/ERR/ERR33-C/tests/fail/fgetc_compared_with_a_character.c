/*
 * Rule: ERR33-C
 * Status: FAIL - `c == '\n'` does not detect EOF, so the fgetc result is
 * stored into buf unchecked.
 */

#include <stdio.h>

int f(FILE *fp, char *buf) {
    int lines = 0;
    int c = fgetc(fp);
    if (c == '\n') {
        lines++;
    }
    buf[0] = (char)c;
    return lines;
}
