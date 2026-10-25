/*
 * Rule: FIO14-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO14-C violation
 * Settings: posix_version=2008
 * Expect: default=violation strict=violation pedantic=violation
 *
 * POSIX relaxes the binary-stream fseek() forms, not this one: its ungetc()
 * leaves the file position unspecified when it was 0 before the call, on
 * every stream.
 */
#include <stdio.h>

void push_back_before_reading(void) {
    FILE *fp = fopen("data.bin", "rb");
    if (fp != NULL) {
        ungetc('x', fp);
        fclose(fp);
    }
}
