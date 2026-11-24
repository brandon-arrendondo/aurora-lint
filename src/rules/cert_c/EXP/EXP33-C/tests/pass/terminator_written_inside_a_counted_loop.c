/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger EXP33-C violation
 *
 * A write at a constant index inside a counted loop is one write, not a
 * partial fill. `data[0] = '\0'` writes the terminator however many times
 * the loop runs, so the append that follows reads an initialized string,
 * whether the buffer is on the stack or from malloc.
 */

#include <stdlib.h>
#include <string.h>

void append_after_one_pass(const char *src) {
    int h;
    char *data;
    char buf[100];
    for (h = 0; h < 1; h++) {
        data = buf;
        data[0] = '\0';
    }
    strncat(data, src, 50);
}

void append_to_an_allocated_buffer(const char *src) {
    int h;
    char *data = malloc(100 * sizeof(char));
    if (data == NULL) {
        return;
    }
    for (h = 0; h < 2; h++) {
        data[0] = '\0';
    }
    strncat(data, src, 50);
    free(data);
}
