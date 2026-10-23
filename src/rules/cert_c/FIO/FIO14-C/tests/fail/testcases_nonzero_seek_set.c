/*
 * Rule: FIO14-C
 * Source: testcases
 * Status: VIOLATION under strict; PASS under the default preset
 * Expect: default=clean strict=violation
 *
 * fseek() with non-zero literal offset and SEEK_SET on text stream
 *
 * The default preset assumes POSIX, where 'b' has no effect and a text
 * stream is a binary one, so it does not report the call. Strict reports it
 * until POSIX is declared.
 */

#include <stdio.h>

void nonzero_seek_set(void) {
    FILE *fp = fopen("notes.txt", "r");
    if (fp == NULL) {
        return;
    }
    /* VIOLATION: non-zero literal offset with SEEK_SET is not portable */
    fseek(fp, 100, SEEK_SET);
    fclose(fp);
}
