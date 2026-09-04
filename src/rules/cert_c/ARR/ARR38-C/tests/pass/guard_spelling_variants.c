/*
 * Rule: ARR38-C
 * Source: sqlite ext/session/sqlite3session.c, plus the other guard spellings
 *         from task 731's delta-adjudication (task 747)
 * Status: PASS - Should NOT trigger ARR38-C violation
 *
 * `has_size_validation` used to search for seven literal substrings --
 * "if (n <", "if (n >=", "n > sizeof" and friends -- so it credited exactly
 * one spelling of a bounds guard and missed every other. `session_varint_get`
 * below is the purest case: it is literally the "if (N <" the pattern set
 * looked for, missed on the absent spaces alone. The rest are the spellings
 * the same adjudication turned up: reversed operands, a compound left-hand
 * side, an `&&` conjunct, an enclosing loop condition, an equality that pins
 * the size exactly, and an assert stating the capacity contract.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct packet {
    size_t len;
};

/* sqlite sessionVarintGetSafe: the guard is missed on whitespace alone. */
void session_varint_get(const unsigned char *a_buf, size_t n_buf) {
    unsigned char a_copy[5];
    if( n_buf<5 ){
        memcpy(a_copy, a_buf, n_buf);
    }
}

/* Reversed operands: the bound is on the left. */
void reversed_operands(const unsigned char *src, size_t n) {
    unsigned char buf[64];
    if (sizeof(buf) >= n) {
        memcpy(buf, src, n);
    }
}

/* Compound left-hand side: the guard tests a member against the size. */
void compound_lhs(const struct packet *p, const unsigned char *src, size_t n) {
    unsigned char buf[64];
    if (p->len < n) {
        return;
    }
    memcpy(buf, src, n);
}

/* The guard is one conjunct of an `&&`, not the whole condition. */
void conjunct_guard(const unsigned char *src, size_t n, int ready) {
    unsigned char buf[64];
    if (ready && n <= sizeof(buf)) {
        memcpy(buf, src, n);
    }
}

/* The guard is the enclosing loop condition, not a preceding statement. */
void loop_bound(const unsigned char *src, size_t n) {
    unsigned char buf[64];
    while (n < sizeof(buf)) {
        memcpy(buf, src, n);
        n++;
    }
}

/* Equality pins the size exactly, which bounds it as well as `<` does. */
void equality_pins_size(const unsigned char *src, size_t n) {
    unsigned char buf[64];
    if (n == 5) {
        memcpy(buf, src, n);
    }
}

/* An assert is the author writing down the capacity contract. */
void asserted_bound(const unsigned char *src, size_t n) {
    unsigned char buf[64];
    assert(n <= sizeof(buf));
    memcpy(buf, src, n);
}

/* The same assert, written under the `#ifndef NDEBUG` sqc never preprocesses. */
void preproc_wrapped_assert(const unsigned char *src, size_t n) {
    unsigned char buf[64];
#ifndef NDEBUG
    assert(n <= sizeof(buf));
#endif
    memcpy(buf, src, n);
}
