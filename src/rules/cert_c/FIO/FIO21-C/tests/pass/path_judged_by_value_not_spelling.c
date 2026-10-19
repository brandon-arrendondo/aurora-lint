/*
 * Rule: FIO21-C
 * Source: regression
 * Status: PASS - Should NOT trigger FIO21-C violation
 *
 * The paths are spelled like temporary names but hold none: a variable
 * named file_name holding a literal outside any shared directory, and one
 * named tmpnam_result whose value is a parameter. A path is judged by where
 * its value comes from, never by its spelling.
 */

#include <stdio.h>

void save(const char *dest) {
    const char *file_name = "/home/user/output.txt";
    const char *tmpnam_result = dest;
    FILE *a = fopen(file_name, "w");
    FILE *b = fopen(tmpnam_result, "a");
    if (a != NULL) {
        fclose(a);
    }
    if (b != NULL) {
        fclose(b);
    }
}
