/*
 * Rule: FIO39-C
 * Status: PASS - Should NOT trigger FIO39-C violation
 *
 * Two different functions each use a same-named FILE* parameter ("fp").
 * f1 performs a single output; f2 performs a single input. Each function's
 * calls are tracked on their own, so f1's output and f2's input on two
 * different streams that happen to share a name are not an alternation.
 */

#include <stdio.h>

void f1(FILE *fp) {
    fprintf(fp, "data: %d\n", 42);
}

void f2(FILE *fp) {
    int value;
    fscanf(fp, "%d", &value);
}
