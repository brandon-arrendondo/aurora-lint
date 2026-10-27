/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: FAIL - a double struct member compared with a double
 * Expect: count=1
 */

struct sample { double value; int count; };

int at_target(const struct sample *s, double target) {
    return s->value == target; /* Expect: here */
}
