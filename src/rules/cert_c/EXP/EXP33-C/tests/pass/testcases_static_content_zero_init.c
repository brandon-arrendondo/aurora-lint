/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. `s_static_arr` is a
 * static array with no explicit initializer, so it is zero-initialized
 * per C11 6.7.9p10 -- its elements are determinate (just possibly not what
 * the programmer intended), unlike an indeterminate auto array. Before
 * task 459, subscript reads of a static's content were flagged the same
 * as a genuinely uninitialized auto array ("Reading from '...' which may
 * contain uninitialized data"), ignoring the standard's zero-init
 * guarantee for static storage duration.
 */

static int s_static_arr[4];

int subscript_static(int i) {
    return s_static_arr[i];
}
