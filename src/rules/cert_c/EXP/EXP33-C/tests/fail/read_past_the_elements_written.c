/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - reads an element of a malloc'd buffer no write covered
 * Expect: count=5
 *
 * A write at a constant index covers that element and no other. Reading
 * one it did not cover reads indeterminate memory, whether the write is in
 * straight-line code or repeated by a loop, through a subscript or a
 * dereference, and whether the read names the element or a variable index
 * that runs past it.
 */

#include <stdlib.h>

void printIntLine(int);

int straight_line(void) {
    int *d = malloc(10 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 0;
    return d[5]; /* Expect: here */
}

void constant_index_in_a_loop(void) {
    int i;
    int *data = malloc(10 * sizeof(int));
    if (data == NULL) {
        exit(-1);
    }
    for (i = 0; i < 5; i++) {
        data[0] = i;
    }
    for (i = 0; i < 10; i++) {
        printIntLine(data[i]); /* Expect: here */
    }
}

void constant_dereference_in_a_loop(void) {
    int i;
    int *data = malloc(10 * sizeof(int));
    if (data == NULL) {
        exit(-1);
    }
    for (i = 0; i < 5; i++) {
        *data = i;
    }
    for (i = 0; i < 10; i++) {
        printIntLine(data[i]); /* Expect: here */
    }
}

int dereference_of_another_element(void) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[1] = 3;
    return *d; /* Expect: here */
}

int one_branch_wrote_it(int c) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    if (c) {
        d[0] = 1;
    } else {
        d[1] = 2;
    }
    return d[2]; /* Expect: here */
}
