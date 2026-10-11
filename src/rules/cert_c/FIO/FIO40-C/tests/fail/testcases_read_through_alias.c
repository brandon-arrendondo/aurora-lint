/*
 * Rule: FIO40-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO40-C violation
 *
 * The failure branch only reports the error, and the array is then read
 * through a pointer holding its address: a read through an alias is a
 * read of the array. Both orders: the pointer taken after the call, and
 * before it.
 */

#include <stdio.h>

void alias_after(char *out) {
    char input[64];
    unsigned char *p;
    if (fgets(input, sizeof(input) - 1, stdin) == NULL) {
        perror("fgets");
    }
    p = (unsigned char *) input;
    while (*p && *p != '\n') {
        *out++ = (char) *p++;
    }
}

void alias_before(void) {
    char line[64];
    const char *cursor = line;
    if (!fgets(line, sizeof line, stdin)) {
        fputs("no input\n", stderr);
    }
    puts(cursor);
}
