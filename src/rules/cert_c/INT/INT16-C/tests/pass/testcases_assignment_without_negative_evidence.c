/*
 * Rule: INT16-C
 * Source: testcases
 * Status: PASS - signed-to-unsigned assignment where no value here can be negative
 *
 * The signed->unsigned assignment check needs evidence that a sign is actually
 * there to be lost. "Some declaration of this name is signed" is not that
 * evidence, and treating it as such made this check fire on essentially every
 * assignment in a real codebase.
 */

struct params {
    unsigned int auth_alg;
    unsigned int state;
};

/* An unconstrained int parameter copied into a field: nothing about auth_alg
   says it can be negative. */
void set_auth_alg(struct params *p, int auth_alg) {
    p->auth_alg = auth_alg;
}

/* The range check the rule asks for is already here, so the value reaching the
   assignment is known non-negative. */
void set_state(struct params *p, int level) {
    if (level < 0) {
        return;
    }
    p->state = level;
}

/* Compound assignment over a pointer is pointer arithmetic, not a conversion --
   the operand's sign is the point of the expression, not a defect in it. */
unsigned long advance(const unsigned char *buf, int len) {
    const unsigned char *pos = buf;
    pos += len;
    return (unsigned long)(pos - buf);
}
