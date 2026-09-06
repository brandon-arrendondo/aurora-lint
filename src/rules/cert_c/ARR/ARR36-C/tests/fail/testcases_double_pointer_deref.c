/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to
 *       the same array
 * Status: FAIL
 * Reason: A dereference spends one level of indirection, and 'char **' has
 *         two, so '*pp_a' and '*pp_b' are still pointers -- into two
 *         different arrays. The counterpart to the single-level case in
 *         pass/testcases_deref_char_params.c: the same '*x' spelling, and a
 *         violation here precisely because the depth differs.
 */

void compare_through_double_pointers(void)
{
    char a[16];
    char b[16];

    char *pa = a;
    char *pb = b;

    char **pp_a = &pa;
    char **pp_b = &pb;

    /* '*pp_a' points into a, '*pp_b' into b: two different arrays. */
    if (*pp_a < *pp_b) {  /* VIOLATION */
        a[0] = 'x';
    }
}

int main(void)
{
    compare_through_double_pointers();
    return 0;
}
