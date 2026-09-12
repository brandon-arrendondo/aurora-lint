/*
 * Rule: EXP02-C
 * Source: testcases
 * Status: FAIL - A side-effect-free call used as a guard does not excuse a
 *   genuine mutation in the right operand
 */

int poll_ready(void);

/* poll_ready() is a legitimate side-effect-free guard, but the increment of
 * *attempts only happens once poll_ready() is true -- it may not execute due
 * to short-circuit evaluation. */
int poll_and_count(int *attempts) {
    if (poll_ready() && (*attempts)++ > 0) {
        return 1;
    }
    return 0;
}
