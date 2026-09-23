/*
 * Rule: FIO50-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO50-C violation
 *
 * fread and fwrite take the stream as their LAST argument. Copying through
 * one buffer from one stream to another reads one stream and writes a
 * different one, so neither stream alternates direction.
 */

#include <stdio.h>

void copy_stream(FILE *in, FILE *out) {
    char buf[256];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        fwrite(buf, 1, n, out);
    }
}

void copy_lines(FILE *in, FILE *out) {
    char line[128];
    while (fgets(line, sizeof(line), in) != NULL) {
        fputs(line, out);
    }
}
