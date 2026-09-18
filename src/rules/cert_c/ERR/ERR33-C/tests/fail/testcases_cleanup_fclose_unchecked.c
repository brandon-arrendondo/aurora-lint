/*
 * Rule: ERR33-C
 * Status: FAIL - fclose on an error/cleanup path still returns EOF on failure
 *
 * ERR33-C-EX1 does not list fclose() among the functions whose return value
 * need not be checked, and "we were already on the error path" is not one of
 * its conditions. Both fclose() calls below ignore the result; the one inside
 * the fgets() error branch is the shape an earlier "cleanup context"
 * heuristic used to suppress (task 727: 13 such sites in one real file).
 */

#include <stdio.h>

int f(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        return -1;
    }

    char buf[256];
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        /* Error path: fclose result silently dropped */
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}
