/*
 * Rule: EXP02-C
 * Source: testcases
 * Status: PASS - A pure predicate/accessor call used as a guard, or a
 *   sequential fallible-step chain, is not a short-circuit side-effect bug
 */

int ttisboolean(void *o);
int bvalue(void *o);

/* Guarding one predicate call with another: the RHS is only reached when
 * the guard call says the object actually is a boolean, and bvalue() reads
 * without mutating anything. This is completely ordinary C. */
int check_boolean(void *o) {
    if (ttisboolean(o) && bvalue(o)) {
        return 1;
    }
    return 0;
}

int step_a(void);
int step_b(void);
int step_c(void);

/* Sequential fallible-step chain: each step is only attempted once every
 * earlier one has failed -- that is the entire point of the idiom, not a
 * missed side effect. */
int run_steps(void) {
    if (step_a() || step_b() || step_c()) {
        return 1;
    }
    return 0;
}
