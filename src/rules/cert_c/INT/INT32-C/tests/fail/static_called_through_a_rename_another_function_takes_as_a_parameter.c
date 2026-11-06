/*
 * Rule: INT32-C
 * Source: aurora-lint
 * Status: FAIL - write_trace takes and calls a pointer named write_all,
 *         but write_body's call of write_all has no such pointer in scope
 *         and goes through the rename to write_some, with values it does
 *         not bound
 * Expect: count=3
 */
static int write_some(int amount, int offset) {
    int wrote = amount / 2;
    amount -= wrote;  /* Expect: here */
    offset += wrote;  /* Expect: here */
    return amount + offset;  /* Expect: here */
}

int write_trace(int (*write_all)(int, int), int len) {
    return write_all(len, 0);
}

#define write_all write_some

int write_body(int len, int pos) {
    return write_all(len, pos);
}

int write_header(void) {
    return write_some(4, 0);
}
