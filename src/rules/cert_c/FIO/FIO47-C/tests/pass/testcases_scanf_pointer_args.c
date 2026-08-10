/*
 * Rule: FIO47-C
 * Source: testcases
 * Status: PASS - scanf-family numeric conversions correctly take pointer
 * arguments (unlike printf-family, where the same specifiers take values
 * by value). FIO47-C must not flag a "type mismatch" here.
 */

#include <stdio.h>

void read_values(void) {
    int i;
    long l;
    unsigned u;
    double d;
    char c;

    scanf("%d", &i);
    scanf("%ld", &l);
    scanf("%u", &u);
    scanf("%lf", &d);
    scanf("%c", &c);
}

void read_from_string(const char *str) {
    int i;
    unsigned x;

    sscanf(str, "%d", &i);
    sscanf(str, "%x", &x);
}

void read_from_file(FILE *fp) {
    int i;

    fscanf(fp, "%d", &i);
}
