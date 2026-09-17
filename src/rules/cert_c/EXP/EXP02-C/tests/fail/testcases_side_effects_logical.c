/*
 * Rule: EXP02-C
 * Source: testcases
 * Status: FAIL - Side effects in short-circuit logical operators
 */

/* Increment in && right operand */
int side_effect_and(int a, int *count) {
    if (a > 0 && ++(*count) > 10) {
        return 1;
    }
    return 0;
}

/* Function call with side effects in && */
int get_next(void);
int side_effect_call(int flag) {
    if (flag && get_next() > 0) {
        return 1;
    }
    return 0;
}
