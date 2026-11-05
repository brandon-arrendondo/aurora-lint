/*
 * Rule: INT32-C
 * Source: aurora-lint
 * Status: PASS - write_some is static and every call passes 4 and 0. A
 *         macro that calls it by name takes no address, so its caller set
 *         stays closed and the arithmetic is bounded by those constants.
 */
static int write_some(int amount, int offset) {
    int wrote = amount / 2;
    amount -= wrote;
    offset += wrote;
    return amount + offset;
}

#define REWRITE_HEADER(fd) ((fd) >= 0 ? write_some(4, 0) : 0)

int write_header(void) {
    return write_some(4, 0);
}
