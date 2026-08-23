/*
 * Rule: API02-C
 * Source: testcases
 * Status: FAIL - Should trigger API02-C violation
 *
 * The trailing-scalar-out-parameter exemption (task 450) only applies to
 * the LAST parameter — a scalar-typed pointer earlier in the list, not
 * immediately followed by its own size, is still a genuine violation:
 * something else could have been (but wasn't) its size argument.
 */

void fill_ints(int *arr, const char *label);
