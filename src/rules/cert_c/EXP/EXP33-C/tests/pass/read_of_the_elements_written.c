/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: PASS - every read takes elements a write covered
 *
 * A terminator written at element 0 is all a string read of the buffer
 * needs. A read of an element that was written is defined. And a write
 * the offset does not describe -- memset, a callee handed the buffer, a
 * fill by a variable index -- covers the whole buffer as before.
 */

#include <stdlib.h>
#include <string.h>

void fill(int *p);

void append_after_the_terminator(const char *src) {
    char *data = malloc(100 * sizeof(char));
    if (data == NULL) {
        return;
    }
    data[0] = '\0';
    strcat(data, src);
    free(data);
}

int elements_that_were_written(void) {
    int *d = malloc(10 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    d[1] = 2;
    return d[0] + d[1] + *d;
}

int written_whole_by_memset(void) {
    int *d = malloc(10 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    memset(d, 0, 10 * sizeof *d);
    return d[5];
}

int written_by_a_callee(void) {
    int *d = malloc(10 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    fill(d);
    return d[5];
}

int written_by_a_variable_index(int n) {
    int i;
    int *d = malloc(10 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    for (i = 1; i < n; i++) {
        d[i] = i;
    }
    return d[5];
}

int each_branch_wrote_it(int c) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    if (c) {
        d[2] = 1;
    } else {
        memset(d, 0, 4 * sizeof *d);
    }
    return d[2];
}
