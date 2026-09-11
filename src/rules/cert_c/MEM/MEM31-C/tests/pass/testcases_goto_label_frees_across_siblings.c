/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: A cleanup label whose frees are written as a run of sibling
 * statements, which is how real cleanup blocks are written. A
 * `labeled_statement` wraps exactly ONE statement, so only `free(first)` is
 * a descendant of `done:`; `second` and `third` are freed by siblings. The
 * label prescan used to see only the first free, so every `goto done`
 * reported `second` and `third` as leaked. Pins that the prescan keeps
 * walking siblings until one cannot fall through.
 *
 * `spans_two_labels` pins the fall-through case: entering at `first_stage:`
 * runs `second_stage:`'s frees too, because a label does not end the path.
 * Its twin in tests/fail/ covers jumping straight to `second_stage:`, which
 * skips the earlier free and must still report.
 */

#include <stdlib.h>

int multi_statement_cleanup(int c) {
    char *first = malloc(16);
    char *second = malloc(16);
    char *third = malloc(16);

    if (first == NULL)
        goto done;
    if (c == 1)
        goto done;

done:
    free(first);
    free(second);
    free(third);
    return 0;
}

int spans_two_labels(int c) {
    char *early = malloc(16);
    char *late = malloc(16);

    if (c == 1)
        goto first_stage;

first_stage:
    free(early);
second_stage:
    free(late);
    return 0;
}
