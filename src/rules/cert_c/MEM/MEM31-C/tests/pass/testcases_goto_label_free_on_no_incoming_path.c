/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: Twin of tests/fail/
 * testcases_goto_label_double_free_on_one_incoming_path.c. Two gotos reach
 * the cleanup label and neither has freed `p`, so the label's free is the
 * only one on every path into it; the fall-through path frees `p` itself
 * and returns before the label. In the second function the goto path did
 * free `p` but then pointed it at a fresh allocation, so the label frees
 * that one. Neither is a double free, and the union of the gotos' freed
 * states must not claim otherwise.
 */

#include <stdlib.h>

int finish(int c) {
    char *p = malloc(8);
    if (!p) return -1;
    if (c == 2) goto out;
    if (c == 1) goto out;
    free(p);
    return 0;
out:
    if (p) free(p);
    return 1;
}

int refreshed(int c) {
    char *p = malloc(8);
    if (!p) return -1;
    if (c == 2) goto out;
    if (c == 1) {
        free(p);
        p = malloc(4);
        goto out;
    }
    free(p);
    return 0;
out:
    if (p) free(p);
    return 1;
}
