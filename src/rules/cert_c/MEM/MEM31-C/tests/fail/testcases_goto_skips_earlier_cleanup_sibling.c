/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: Twin of tests/pass/
 * testcases_goto_label_frees_across_siblings.c. The sibling walk that
 * teaches the label prescan about a multi-statement cleanup block must not
 * over-credit: jumping into the MIDDLE of the chain runs only the frees
 * from that label onward. `goto second_stage` skips `free(early)`, so
 * `early` really is leaked on that path and must still be reported.
 */

#include <stdlib.h>

int jumps_past_a_free(int c) {
    char *early = malloc(16);
    char *late = malloc(16);

    if (c == 2)
        goto second_stage;

first_stage:
    free(early);
second_stage:
    free(late);
    return 0;
}
