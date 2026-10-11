/*
 * Rule: FIO40-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO40-C violation
 *
 * The file defines its own function named fgets, so the call reaches that
 * function, not the library's, and says nothing about the library read's
 * failure contract.
 */

#include <stddef.h>

struct stream;
int next_char(struct stream *s);

static char *fgets(char *buf, int n, struct stream *s) {
    int i = 0;
    while (i < n - 1) {
        int c = next_char(s);
        if (c < 0) {
            break;
        }
        buf[i++] = (char) c;
    }
    buf[i] = '\0';
    return i ? buf : NULL;
}

void use(const char *line);

void read_line(struct stream *s) {
    char buf[64];
    if (fgets(buf, 64, s) == 0) {
        use(buf);
    }
}
