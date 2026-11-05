/*
 * Rule: INT32-C
 * Source: aurora-lint
 * Status: PASS - write_some is static and every call passes 4 and 0. A
 *         rename nothing uses as a value, and a macro whose argument brings
 *         the call's parentheses, take no address, so its caller set stays
 *         closed and the arithmetic is bounded by those constants.
 */
static int write_some(int amount, int offset) {
    int wrote = amount / 2;
    amount -= wrote;
    offset += wrote;
    return amount + offset;
}

#define write_all write_some
#define WRITE_TRACED(args) do { (void)write_some args; } while (0)

int write_header(void) {
    WRITE_TRACED((4, 0));
    return write_some(4, 0);
}
