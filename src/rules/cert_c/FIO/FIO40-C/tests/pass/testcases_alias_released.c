/*
 * Rule: FIO40-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO40-C violation
 *
 * A pointer that held the array's address is pointed elsewhere before it
 * is read on the failure path, and a pointer stepped through the array is
 * only read on the success path.
 */

#include <stdio.h>

static const char fallback[] = "none";

void alias_reassigned(void) {
    char line[64];
    const char *text = line;
    if (fgets(line, sizeof line, stdin) == NULL) {
        text = fallback;
    }
    puts(text);
}

int count_digits(void) {
    char line[64];
    const char *p = line;
    int n = 0;
    if (fgets(line, sizeof line, stdin) == NULL) {
        return -1;
    }
    for (; *p; p++) {
        n += (*p >= '0' && *p <= '9');
    }
    return n;
}
