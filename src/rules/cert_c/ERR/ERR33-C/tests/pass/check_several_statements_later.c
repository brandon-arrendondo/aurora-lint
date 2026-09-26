/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: PASS
 * Reason: The NULL test comes several statements after the fopen, with no write to the pointer in between.
 */

#include <stdio.h>

int count_lines(const char *path, int verbose, int *lines) {
    FILE *f = fopen(path, "r");
    int n = 0;
    int c;
    *lines = 0;
    verbose = verbose ? 1 : 0;
    n += verbose;
    if (f == NULL) {
        return -1;
    }
    while ((c = fgetc(f)) != EOF) {
        if (c == '\n') {
            n++;
        }
    }
    *lines = n;
    return fclose(f);
}
