/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: NEXT increments a counter, and ABS evaluates its argument twice.
 */

static int counter;

#define NEXT() (counter++)
#define ABS(x) (((x) < 0) ? -(x) : (x))

int a(void) {
    return ABS(NEXT());  // VIOLATION
}
