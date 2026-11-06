/*
 * Rule: INT32-C
 * Source: aurora-lint
 * Status: PASS - write_some is static and is called directly with 4 and 0
 *         and through the rename write_all with 6 and 1. write_trace's
 *         call of write_all, with one argument, is through its own pointer
 *         parameter of that name, not a call to write_some, so the
 *         arithmetic stays bounded by the constants.
 */
static int write_some(int amount, int offset) {
    int wrote = amount / 2;
    amount -= wrote;
    offset += wrote;
    return amount + offset;
}

int write_trace(int (*write_all)(int), int len) {
    return write_all(len);
}

#define write_all write_some

int write_body(void) {
    return write_all(6, 1);
}

int write_header(void) {
    return write_some(4, 0);
}
