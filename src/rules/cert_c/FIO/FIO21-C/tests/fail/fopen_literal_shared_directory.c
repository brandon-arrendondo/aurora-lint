/*
 * Rule: FIO21-C
 * Source: regression
 * Status: FAIL - Should trigger FIO21-C violation
 *
 * A file created in write mode at a literal path under /tmp, the
 * construct FIO15-C leaves to FIO21-C.
 */

#include <stdio.h>

void write_report(const char *text) {
    FILE *fp = fopen("/tmp/report.txt", "w");
    if (fp != NULL) {
        fputs(text, fp);
        fclose(fp);
    }
}
