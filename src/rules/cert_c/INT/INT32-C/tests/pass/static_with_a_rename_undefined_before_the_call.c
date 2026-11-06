/*
 * Rule: INT32-C
 * Source: aurora-lint
 * Status: PASS - write_some is static and its one call passes 4 and 0. The
 *         rename write_all is #undef'd before write_all is declared and
 *         called as a function of its own, so that call is not to
 *         write_some, and the arithmetic stays bounded by the constants.
 */
static int write_some(int amount, int offset) {
    int wrote = amount / 2;
    amount -= wrote;
    offset += wrote;
    return amount + offset;
}

#define write_all write_some
#undef write_all

extern int write_all(int amount, int offset);

int write_body(int len, int pos) {
    return write_all(len, pos) + write_some(4, 0);
}
