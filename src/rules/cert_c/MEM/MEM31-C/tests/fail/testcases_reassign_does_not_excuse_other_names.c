/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: Twin of tests/pass/
 * testcases_reassign_from_opaque_call_clears_freed.c, bounding how much an
 * assignment is allowed to excuse. Clearing freed-state on assignment is
 * only sound for the name being ASSIGNED, and only for a plain `=`.
 *
 * Both functions below are genuine double frees that must still report:
 * the first assigns some OTHER variable between the two frees, the second
 * uses a compound assignment, which adjusts the pointer that was freed
 * rather than replacing it.
 */

#include <stdlib.h>

char *opaque_dup(const char *s);

int other_name_reassigned(const char *tok) {
    char *p = malloc(16);
    char *q = NULL;

    free(p);

    /* Assigning q says nothing about p. */
    q = opaque_dup(tok);
    free(q);

    /* Still the second free of the same block. */
    free(p);
    return 0;
}

int compound_assignment_keeps_the_pointer(void) {
    char *p = malloc(16);

    free(p);

    /* Not a replacement -- p still points into the freed block. */
    p += 1;

    free(p);
    return 0;
}
