/*
 * Rule: ARR30-C
 * Status: FAIL - Should trigger ARR30-C violation
 */

/*
 * Reason: the counterpart to pass/param_index_from_a_bounded_loop_caller.c.
 * The caller always passes YES, so the `else` arm is unreachable and keeps
 * no ranges, and `option` enters in [0, 39]. But the body also uses
 * `SHIFT_OPTION()`, which nothing in this scan declares: a header macro can
 * assign `option`, so its entry range is not known to hold in that arm.
 */

#define NOPTS 40
#define YES 1

struct negotiation {
    int us[256];
};

static void set_option(struct negotiation *n, int option, int newstate)
{
    SHIFT_OPTION();
    if (newstate == YES) {
        n->us[0] = 2;
    } else {
        n->us[option] = 3;
    }
}

void negotiate(struct negotiation *n)
{
    int i;
    for (i = 0; i < NOPTS; i++)
        set_option(n, i, YES);
}
