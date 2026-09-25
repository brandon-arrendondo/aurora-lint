/*
 * Rule: EXP34-C
 * Source: testcases (dereference inside an assert-style macro's argument)
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * serverAssert here cannot be compiled out, so it guards what FOLLOWS it
 * (ADR-0011 basis 3). Its argument, though, is evaluated before the check:
 * `serverAssert(c->bufpos == 0)` dereferences `c` with nothing proving it
 * non-null. valkey's networking.c clientHasPendingReplies() is the shape.
 */

#include <stdlib.h>

void report(const char *estr);
#define serverAssert(_e) ((_e) ? (void)0 : (report(#_e), abort()))

struct client {
    int bufpos;
};

int pending(void) {
    struct client *c = malloc(sizeof *c);
    serverAssert(c->bufpos == 0);
    return 1;
}

/*
 * An operand of `||` need not hold: `e != NULL || fallback` proves nothing
 * about `e`.
 */
int or_operand(int fallback) {
    struct client *e = malloc(sizeof *e);
    serverAssert(e != NULL || fallback);
    return e->bufpos;
}
