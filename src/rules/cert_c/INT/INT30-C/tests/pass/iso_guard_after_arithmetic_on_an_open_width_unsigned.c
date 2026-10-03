/*
 * Rule: INT30-C
 * Source: regression
 * Status: PASS - no data model is declared
 *
 * Without a declared data model an unsigned type has no known width, so the
 * side of its range that no guard bounds is the type's own limit, whatever
 * the width is. Arithmetic on the variable before the guard moves that limit
 * by the constant involved, and the guard still bounds the value from below:
 * after `len < 1` returns, `len - 1` cannot wrap.
 */

typedef unsigned long size_t;

void consume(const unsigned char *data, size_t n);

void after_a_guarded_subtraction(const unsigned char *data, size_t len) {
    if (len < 4) {
        return;
    }
    data += 4;
    len = len - 4;
    if (len < 1) {
        return;
    }
    consume(data + 1, len - 1);
}

void after_a_second_guarded_subtraction(const unsigned char *data, size_t len) {
    if (len < 8) {
        return;
    }
    len = len - 8;
    if (len < 1) {
        return;
    }
    consume(data, len - 1);
}
