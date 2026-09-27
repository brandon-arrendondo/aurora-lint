/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * verbose is written through SET_VERBOSE(), whose body the parser sees as
 * one token. It is not a constant 0, so the branch that reads the
 * uninitialized x is live.
 */

static int verbose = 0;
#define SET_VERBOSE() (verbose = 1)

int use(int v);

void enable(void) { SET_VERBOSE(); }

int f(void) {
    int x;
    if (verbose) return use(x);
    return 0;
}
