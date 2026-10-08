/*
 * Rule: ARR30-C
 * Status: FAIL - Should trigger ARR30-C violation
 */

/*
 * Reason: `SAVE()`, used before the loop, expands to `p = &i`, and the loop
 * body writes 300 through `p` before the call, so `set_option` receives
 * 300. No `&i` is spelled where the loop is, and no macro is used in it:
 * only the macro outside the loop reaches the counter.
 */

#define SAVE() (p = &i)

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
    int *p = 0;
    SAVE();
    for (i = 0; i < 40; i++) {
        *p = 300;
        set_option(n, i);
    }
}
