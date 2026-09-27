/*
 * Rule: ERR33-C
 * Status: PASS - EOF is detected by `== EOF`, by an ordering test, by a
 * `case EOF:`, and a scanf count is checked against the number of
 * conversions asked for.
 */

#include <stdio.h>

int f(FILE *fp, int *x, int *y) {
    int a = fgetc(fp);
    if (a == EOF) {
        return 1;
    }
    int b = fgetc(fp);
    if (b < 0) {
        return 1;
    }
    int c = fgetc(fp);
    switch (c) {
    case EOF:
        return 1;
    case 'a':
        return 2;
    }
    int d = fputs("x", fp);
    if (EOF == d) {
        return 1;
    }
    int n = fscanf(fp, "%d %d", x, y);
    if (n == 2) {
        return 0;
    }
    return 1;
}
