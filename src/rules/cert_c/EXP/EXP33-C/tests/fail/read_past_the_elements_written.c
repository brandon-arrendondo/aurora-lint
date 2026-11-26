/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - reads an element of a malloc'd buffer no write covered
 * Expect: count=13
 *
 * A write at a constant index covers that element and no other. Reading
 * one it did not cover reads indeterminate memory, whether the write is in
 * straight-line code or repeated by a loop, through a subscript or a
 * dereference, and whether the read names the element or a variable index
 * that runs past it. A call that only reads through a pointer into the
 * buffer writes none of it. A read through a pointer sum takes its element
 * as a subscript does, a store through one covers only its own, an
 * element of a struct array is one element, and a variable index reports
 * when its values may leave the elements written or are not known.
 */

struct pair {
    int a;
    int b;
};

#include <stdlib.h>
#include <string.h>

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

int read_only_callee_past_the_start(void) {
    int *d = malloc(10 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    (void)strlen((const char *)(d + 1));
    return d[5]; /* Expect: here */
}

int pointer_sum_read(void) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    return *(d + 2); /* Expect: here */
}

int pointer_sum_read_offset_first(void) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    return *(2 + d); /* Expect: here */
}

int pointer_sum_read_of_nothing_written(void) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    return *(d + 1); /* Expect: here */
}

int past_a_pointer_sum_store(void) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    *(d + 1) = 2;
    return d[2]; /* Expect: here */
}

int next_struct_element(void) {
    struct pair *s = malloc(4 * sizeof *s);
    if (s == NULL) {
        return 0;
    }
    s[0].a = 1;
    return s[1].a; /* Expect: here */
}

int index_that_leaves_the_elements_written(void) {
    int i;
    int s = 0;
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    d[1] = 2;
    for (i = 0; i < 4; i++) {
        s += d[i]; /* Expect: here */
    }
    return s;
}

int index_known_to_be_unwritten(void) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    d[1] = 1;
    int i = 2;
    return d[i]; /* Expect: here */
}
