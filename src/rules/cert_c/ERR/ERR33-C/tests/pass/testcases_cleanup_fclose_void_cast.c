/*
 * Rule: ERR33-C
 * Status: PASS - fclose on the cleanup path explicitly discarded, main path checked
 *
 * The compliant way to ignore fclose() on an error path is to say so with a
 * (void) cast (ERR33-C-EX1's stated convention), not to leave the call bare.
 */

#include <stdio.h>

int f(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        return -1;
    }

    char buf[256];
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        /* Already failing; discarding the close status is a stated decision */
        (void)fclose(fp);
        return -1;
    }

    if (fclose(fp) == EOF) {
        return -1;
    }
    return 0;
}
