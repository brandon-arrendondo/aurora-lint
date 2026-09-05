// sqc-test: prescan
// Needs the project context a real scan builds: the INT3x provenance gate
// runs in every configuration now, and without context it has no summaries
// to resolve this file's own callees against.
/* Rule: INT32-C
 * Source: testcases (task 926)
 * Status: FAIL - the promoted-int result is stored back into a narrower
 * type, so it can lose data on the conversion.
 *
 * The arithmetic itself is safe (see tests/pass/narrow_promotion_safe.c);
 * what is not safe is the store. On the letter of the standard that is a
 * conversion and so INT31-C's, but no rule owns it yet, and this shape is
 * Juliet's entire CWE-190 short/char cohort. INT32-C keeps reporting it,
 * checked against the destination's width, until the narrow-truncating-store
 * task decides where it belongs -- at which point these cases move with it.
 */

/* 32000 + 1000 = 33000, past SHRT_MAX. */
short trunc_store_add(void) {
    short a = 32000;
    short b = 1000;
    short result = a + b;
    return result;
}

/* CHAR_MAX + 1 does not fit back in a char. */
char trunc_store_char(void) {
    char data = 127;
    char result = data + 1;
    return result;
}

/* Assignment form of the same store. */
short trunc_store_assign(void) {
    short a = 30000;
    short b = 30000;
    short result;
    result = a + b;
    return result;
}

/* Returning into a narrow return type truncates exactly like an assignment. */
short trunc_store_return(void) {
    short a = 20000;
    short b = 20000;
    return a + b;
}

/* Narrow struct field destination. */
struct counters {
    short int total;
};

void trunc_store_field(struct counters *c) {
    short a = 30000;
    short b = 30000;
    c->total = a + b;
}
