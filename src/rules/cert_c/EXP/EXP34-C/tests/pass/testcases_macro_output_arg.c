// sqc-test: prescan
/*
 * Rule: EXP34-C
 * Source: testcases (task 195 Part A -- macro write-through-param)
 * Status: PASS - Should NOT trigger EXP34-C
 *
 * GET_PTR writes through its first argument (a deref write, `*(pp) = val`),
 * mirroring the same idiom `FunctionSummary::modifies_params` recognizes for
 * real functions (task 195 Part B). Calling it with `&p` proves `p` is
 * non-null before the subsequent dereference.
 */

#define GET_PTR(pp, val) do { *(pp) = (val); } while (0)

int *compute(void);

void use_ptr(void) {
    int *p;
    GET_PTR(&p, compute());
    *p = 5;
}
