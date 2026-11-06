/*
 * Rule: INT32-C
 * Source: aurora-lint
 * Status: PASS - write_some is static and is called directly with 4 and 0
 *         and through the rename write_all with 6 and 1. A call through a
 *         rename is a call, not an escaped address, so the caller set stays
 *         closed and the arithmetic is bounded by those constants.
 */
static int write_some(int amount, int offset) {
    int wrote = amount / 2;
    amount -= wrote;
    offset += wrote;
    return amount + offset;
}

#define write_all write_some

int write_body(void) {
    return write_all(6, 1);
}

int write_header(void) {
    return write_some(4, 0);
}
