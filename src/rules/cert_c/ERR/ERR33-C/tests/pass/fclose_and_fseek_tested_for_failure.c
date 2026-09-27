/*
 * Rule: ERR33-C
 * Status: PASS - `!= 0`, `< 0`, `== EOF` and `>= 0` all separate failure
 * from success for fclose and fseek.
 */

#include <stdio.h>

int f(FILE *a, FILE *b, FILE *c, FILE *d) {
    int r = fclose(a);
    if (r != 0) {
        return 1;
    }
    int s = fclose(b);
    if (s < 0) {
        return 1;
    }
    int t = fclose(c);
    if (t == EOF) {
        return 1;
    }
    int u = fseek(d, 0, SEEK_SET);
    if (u >= 0) {
        return 0;
    }
    return 1;
}
