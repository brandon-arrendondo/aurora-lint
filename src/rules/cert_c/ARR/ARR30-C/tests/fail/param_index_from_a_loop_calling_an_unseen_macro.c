/*
 * Rule: ARR30-C
 * Status: FAIL - Should trigger ARR30-C violation
 */

/*
 * Reason: `BUMP()` is declared nowhere this scan can see: a macro from a
 * header outside it can expand to `(i += 300)`, so the loop's `i < 40`
 * proves nothing about what `set_option` receives.
 */

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
    for (i = 0; i < 40; i++) {
        BUMP();
        set_option(n, i);
    }
}
