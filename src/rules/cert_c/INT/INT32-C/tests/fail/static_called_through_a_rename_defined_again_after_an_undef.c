/*
 * Rule: INT32-C
 * Source: aurora-lint
 * Status: FAIL - write_all is #undef'd and then defined again as a rename
 *         of write_some, and an #undef in an arm the file proves is never
 *         compiled undoes nothing, so write_body's call is to write_some
 *         with values it does not bound
 * Expect: count=3
 */
static int write_some(int amount, int offset) {
    int wrote = amount / 2;
    amount -= wrote;  /* Expect: here */
    offset += wrote;  /* Expect: here */
    return amount + offset;  /* Expect: here */
}

#define write_all write_some
#undef write_all
#define write_all write_some
#if 0
#undef write_all
#endif

int write_body(int len, int pos) {
    return write_all(len, pos);
}

int write_header(void) {
    return write_some(4, 0);
}
