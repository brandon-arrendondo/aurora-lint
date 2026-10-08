/*
 * Rule: ARR30-C
 * Status: PASS - Should NOT trigger ARR30-C violation
 */

/*
 * Reason: the static callee's only caller passes the counter of
 * `for (i = 0; i < NOPTS; i++)`, so `option` is in [0, 39] on entry and never
 * written after. The caller also always passes YES, which leaves the callee's
 * `else` arm unreachable; the parameter's entry range still holds there.
 */

#define NOPTS 40
#define YES 1

struct negotiation {
    int us[256];
    int preferred[256];
};

static void set_option(struct negotiation *n, int option, int newstate)
{
    if (newstate == YES) {
        n->us[option] = 2;
    } else {
        n->us[option] = 3;
    }
}

void negotiate(struct negotiation *n)
{
    int i;
    for (i = 0; i < NOPTS; i++) {
        if (n->preferred[i] == YES)
            set_option(n, i, YES);
    }
}
