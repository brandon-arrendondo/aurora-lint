/*
 * Rule: DCL11-C
 * Source: testcases
 * Status: PASS - Should NOT trigger DCL11-C violation
 *
 * A '*' field width or precision consumes an int argument of its own, ahead
 * of the conversion's argument (C11 7.21.6.1p5), so "%*s" takes two
 * arguments, not one. The first call is the shape of a user's report: a
 * size_t length cast to int for the width. "%m" (glibc, syslog) prints
 * strerror(errno) and takes none. A scanf '*' suppresses the assignment, and
 * this rule checks only the printf family.
 */
#include <stdio.h>
#include <stddef.h>

void print_padded(const char *buf, size_t n) {
    printf("%*s\n", (int)n, buf);
}

void print_prefix(void) {
    const char *name = "websocket";
    int len = 3;
    int width = 10;
    double ratio = 0.5;

    printf("%.*s\n", len, name);
    printf("%*d\n", width, len);
    printf("%*.*f\n", width, len, ratio);
    printf("%-*s|\n", width, name);
    printf("failed: %m\n");
}

void read_second(const char *buf) {
    int second;
    sscanf(buf, "%*d %d", &second);
}
