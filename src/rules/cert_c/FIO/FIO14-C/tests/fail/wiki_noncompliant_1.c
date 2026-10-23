/*
 * Rule: FIO14-C
 * Source: wiki
 * Status: VIOLATION under strict; PASS under the default preset
 * Expect: default=clean strict=violation
 *
 * Using fseek() with SEEK_END on binary stream is undefined behavior
 *
 * The default preset assumes POSIX, where 'b' has no effect and a text
 * stream is a binary one, so it does not report the call. Strict reports it
 * until POSIX is declared.
 */

#include <stdio.h>

void noncompliant_binary_seek_end(void) {
    FILE *fp = fopen("data.bin", "rb");
    if (fp != NULL) {
        /* VIOLATION: fseek() with SEEK_END on binary stream */
        fseek(fp, 0, SEEK_END);
        fclose(fp);
    }
}
