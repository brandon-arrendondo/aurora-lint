/*
 * Rule: FIO50-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO50-C violation
 *
 * fputs and fgets take the stream as their LAST argument. Output to fp
 * followed by input from fp, through different buffers, is still an
 * alternation on the one stream.
 */

#include <stdio.h>

void write_then_read(FILE *fp) {
    char reply[64];
    fputs("PING\n", fp);
    /* VIOLATION: input on fp follows output with no fflush/fseek between */
    fgets(reply, sizeof(reply), fp);
}
