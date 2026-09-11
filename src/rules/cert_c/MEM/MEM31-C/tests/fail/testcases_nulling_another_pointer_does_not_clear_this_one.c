/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: Twin of tests/pass/testcases_free_then_null_is_not_a_double_free.c.
 * `q = NULL` says nothing about `p`: the second `free(p)` is still a double
 * free. Pins that clearing the freed mark on a NULL assignment is keyed on
 * the assigned name, not on any NULL assignment in between.
 */

#include <stdlib.h>

void nulls_the_wrong_one(char *p, char *q) {
    free(p);
    q = NULL;
    free(p);
}
