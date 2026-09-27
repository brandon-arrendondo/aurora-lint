/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: REMEMBER writes the global `last` (under an if), and ABS
 * evaluates its argument twice.
 */

static int last;

#define REMEMBER(v) ({ if (v) last = (v); (v); })
#define ABS(x) (((x) < 0) ? -(x) : (x))

int a(int n) {
    return ABS(REMEMBER(n));  // VIOLATION
}
