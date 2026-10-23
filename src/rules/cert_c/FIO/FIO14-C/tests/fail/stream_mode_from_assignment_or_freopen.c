/*
 * Rule: FIO14-C
 * Source: testcases
 * Status: VIOLATION under strict; PASS under the default preset
 * Expect: default=clean strict=violation
 *
 * The stream's mode comes from the fopen() assigned to it, or the freopen()
 * that reopens it: SEEK_END on a binary stream, and an arbitrary SEEK_SET
 * offset on a text stream.
 *
 * The default preset assumes POSIX, where 'b' has no effect and a text
 * stream is a binary one, so it does not report the call. Strict reports it
 * until POSIX is declared.
 */
#include <stdio.h>

void seek_end_of_assigned_binary(void) {
    FILE *fp;
    fp = fopen("data.bin", "r+b");
    if (fp != NULL) {
        fseek(fp, 0, SEEK_END);
        fclose(fp);
    }
}

void seek_set_on_reopened_text(FILE *fp) {
    if (freopen("notes.txt", "w+", fp) != NULL) {
        fseek(fp, 12, SEEK_SET);
    }
}
