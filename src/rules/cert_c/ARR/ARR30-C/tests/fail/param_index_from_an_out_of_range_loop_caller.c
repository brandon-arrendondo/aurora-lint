/*
 * Rule: ARR30-C
 * Status: FAIL - Should trigger ARR30-C violation
 */

/*
 * Reason: the counterpart to pass/param_index_from_a_bounded_loop_caller.c.
 * The only caller's loop runs its counter to 299, past the 256-entry array,
 * so the caller's range proves nothing. Recording the counter as the 0 it
 * starts from, because `i++` is not a constant assignment, hid this.
 */

#define NOPTS 300

struct negotiation {
    int us[256];
};

static void set_option(struct negotiation *n, int option)
{
    n->us[option] = 2;
}

void negotiate(struct negotiation *n)
{
    int i;
    for (i = 0; i < NOPTS; i++) {
        set_option(n, i);
    }
}
