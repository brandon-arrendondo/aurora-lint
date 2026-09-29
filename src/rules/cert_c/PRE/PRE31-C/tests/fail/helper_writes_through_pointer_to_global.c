/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: init writes through its pointer, and reset hands it the address
 * of the global counter, so reset writes counter: a proven side effect.
 */

#define TWICE(x) ((x) + (x))

int counter;

static void init(int *p) {
    *p = 0;
}

int reset(void) {
    init(&counter);
    return counter;
}

int use(void) {
    return TWICE(reset());  // VIOLATION
}
