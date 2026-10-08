/*
 * Rule: ARR30-C
 * Status: FAIL - Should trigger ARR30-C violation
 */

/*
 * Reason: Duff's device. The `case 1:` label sits inside the loop but
 * belongs to the switch outside it, so `x == 1` jumps into the loop body
 * past `i = 0` with `i` still 1000. The loop's `i < 40` proves nothing about
 * the call it skips to, and `option` can be 1000.
 */

struct negotiation {
    int us[256];
};

static void set_option(struct negotiation *n, int option)
{
    n->us[option] = 2;
}

void negotiate(struct negotiation *n, int x)
{
    int i = 1000;
    switch (x) {
    case 0:
        for (i = 0; i < 40; i++) {
    case 1:
            set_option(n, i);
        }
    }
}
