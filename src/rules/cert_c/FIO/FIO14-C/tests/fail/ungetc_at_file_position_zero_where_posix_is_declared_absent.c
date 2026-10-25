/*
 * Rule: FIO14-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO14-C violation
 * Settings: posix_version=none
 * Expect: default=violation strict=violation pedantic=violation
 *
 * The target is declared not POSIX: the position of a binary stream that
 * was 0 before ungetc() is indeterminate after it (C11 7.21.7.10p5).
 */
#include <stdio.h>

void push_back_before_reading(void) {
    FILE *fp = fopen("data.bin", "rb");
    if (fp != NULL) {
        ungetc('x', fp);
        fclose(fp);
    }
}
