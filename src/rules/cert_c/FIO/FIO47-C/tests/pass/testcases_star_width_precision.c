/*
 * Rule: FIO47-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO47-C violation
 *
 * A '*' field width or precision in a printf-family format consumes an int
 * argument of its own, ahead of the conversion's argument (C11 7.21.6.1p5).
 * In scanf, a '*' right after '%' suppresses the assignment, so that
 * conversion consumes no argument at all (C11 7.21.6.2p3).
 */
#include <stdio.h>

void print_prefix(void) {
    const char *name = "websocket";
    int len = 3;
    int width = 10;
    double ratio = 0.5;

    printf("%.*s\n", len, name);
    printf("%*d\n", width, len);
    printf("%*.*f\n", width, len, ratio);
    printf("%-*s|\n", width, name);
}

void read_second(const char *buf) {
    int second;
    sscanf(buf, "%*d %d", &second);
}
