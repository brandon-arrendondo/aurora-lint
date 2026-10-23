/*
 * Rule: FIO14-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO14-C violation
 * Settings: posix_version=2008
 *
 * POSIX is declared: 'b' in a mode has no effect there, and a binary stream
 * is a text stream, so SEEK_END and any SEEK_SET offset are defined.
 */
#include <stdio.h>

void seek_end_of_binary(void) {
    FILE *fp = fopen("data.bin", "rb");
    if (fp != NULL) {
        fseek(fp, 0, SEEK_END);
        fseek(fp, 100, SEEK_SET);
        fclose(fp);
    }
}
