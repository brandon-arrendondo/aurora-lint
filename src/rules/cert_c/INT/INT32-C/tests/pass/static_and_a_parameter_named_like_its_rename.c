/*
 * Rule: INT32-C
 * Source: aurora-lint
 * Status: PASS - write_some is static and its one call passes 4 and 0.
 *         write_body's parameter is named like the rename write_all, so the
 *         rename renames the parameter too, and write_all(len, pos) calls
 *         through the pointer, not write_some: the arithmetic stays bounded
 *         by the constants.
 */
static int write_some(int amount, int offset) {
    int wrote = amount / 2;
    amount -= wrote;
    offset += wrote;
    return amount + offset;
}

#define write_all write_some

int write_body(int (*write_all)(int, int), int len, int pos) {
    return write_all(len, pos);
}

int write_header(void) {
    return write_some(4, 0);
}
