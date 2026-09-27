/*
 * Rule: ERR33-C
 * Status: FAIL - a switch on the fgetc result with no case for EOF does not
 * detect it.
 */

#include <stdio.h>

int f(FILE *fp) {
    int c = fgetc(fp);
    switch (c) {
    case 'a':
        return 1;
    default:
        return 0;
    }
}
