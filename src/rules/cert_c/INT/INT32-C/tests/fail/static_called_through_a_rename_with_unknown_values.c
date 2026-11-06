/*
 * Rule: INT32-C
 * Source: aurora-lint
 * Status: FAIL - write_body calls write_some through the rename write_all
 *         with values it does not bound, so write_some's parameters are not
 *         bounded by write_header's constants
 * Expect: count=3
 */
static int write_some(int amount, int offset) {
    int wrote = amount / 2;
    amount -= wrote;  /* Expect: here */
    offset += wrote;  /* Expect: here */
    return amount + offset;  /* Expect: here */
}

#define write_all write_some

int write_body(int len, int pos) {
    return write_all(len, pos);
}

int write_header(void) {
    return write_some(4, 0);
}
