/*
 * Rule: FIO50-C
 * Task: 409
 * Status: PASS - Should NOT trigger FIO50-C violation
 *
 * Two different functions each use a same-named FILE* parameter ("fp").
 * f1 performs a single output; f2 performs a single input. Neither
 * function alone has an alternation to flag (a single operation can't
 * violate FIO50-C). Prior to the task-409 fix, `traverse` matched both
 * `function_definition` and `translation_unit` as scope boundaries, and
 * since the root passed to `traverse` is itself a translation_unit,
 * `analyze_scope` also ran once over the *whole file* as one merged
 * scope. In that merged, file-wide operation sequence, f1's trailing
 * output on "fp" became immediately adjacent (in AST traversal/source
 * order) to f2's leading input on "fp", producing a false
 * output-then-input alternation violation across an unrelated function
 * boundary. With per-function scoping, each function's own operation
 * list has only one element, so `detect_alternation_violations` (which
 * only ever compares *consecutive* operations within a single scope) has
 * no pair to flag in either function.
 */

#include <stdio.h>

void f1(FILE *fp) {
    fprintf(fp, "data: %d\n", 42);
}

void f2(FILE *fp) {
    int value;
    fscanf(fp, "%d", &value);
}
