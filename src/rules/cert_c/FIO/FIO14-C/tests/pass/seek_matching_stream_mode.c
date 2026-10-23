/*
 * Rule: FIO14-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO14-C violation
 *
 * SEEK_END is defined on a text stream, and any SEEK_SET offset on a binary
 * stream (C11 7.21.9.2). A stream whose mode is not known here, such as a
 * parameter, or one a mode chosen at run time opened, is not reported.
 */
#include <stdio.h>

long text_length(void) {
    long len = -1;
    FILE *fp = fopen("notes.txt", "r");
    if (fp != NULL) {
        fseek(fp, 0, SEEK_END);
        len = ftell(fp);
        fclose(fp);
    }
    return len;
}

void binary_record(void) {
    FILE *fp = fopen("data.bin", "rb");
    if (fp != NULL) {
        fseek(fp, 512, SEEK_SET);
        fclose(fp);
    }
}

void unknown_mode(FILE *fp, const char *mode) {
    FILE *other = fopen("data", mode);
    fseek(fp, 0, SEEK_END);
    fseek(fp, 100, SEEK_SET);
    if (other != NULL) {
        fseek(other, 0, SEEK_END);
        fclose(other);
    }
}
