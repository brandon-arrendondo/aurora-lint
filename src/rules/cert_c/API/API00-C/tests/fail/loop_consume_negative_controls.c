/*
 * Rule: API00-C
 * Source: custom
 * Status: FAIL - SHOULD trigger API00-C violation
 * Description: Negative controls for the loop-consume idiom (task 740). Each
 * of these is one loop away from the suppressed shape and must keep firing:
 * a loop whose condition tests the parameter but whose body never draws it
 * down, a body that reassigns it from elsewhere, a parameter in the
 * subtrahend position, and an equality break against a third value rather
 * than against the subtraction's own operands.
 */

extern size_t get_more(void);
extern void sink(size_t v);

/* No drawdown of len: `while (len)` says only len >= 1. Must still fire. */
void no_drain(size_t len)
{
    while (len) {
        sink(len - offset);
        offset++;
    }
}

/* Reassigned from elsewhere inside the loop: not monotonic. Must still fire. */
void reassigned(size_t len)
{
    size_t n = 1;
    while (len) {
        len -= n;
        len = get_more();
    }
}

/* Parameter is the subtrahend, not the minuend. Must still fire. */
void subtrahend_param(size_t take)
{
    size_t have = 100;
    while (have) {
        have -= take;
        sink(have - take);
    }
}

/* Equality against a third value, not the subtraction's own operands.
   Must still fire. */
void unrelated_equality(size_t outlen)
{
    size_t pos = 0, clen;
    for (;;) {
        if (pos == 7)
            break;
        clen = outlen - pos;
        pos += clen;
    }
}
