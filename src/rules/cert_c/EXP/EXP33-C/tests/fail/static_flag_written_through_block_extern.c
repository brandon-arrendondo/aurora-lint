/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * The block-scope extern declaration names the file-scope debug, so
 * on() writes it. It is not a constant 0, so the branch that reads the
 * uninitialized x is live.
 */

static int debug = 0;

int use(int v);

void on(void) {
    extern int debug;
    debug = 1;
}

int f(void) {
    int x;
    if (debug) return use(x);
    return 0;
}
