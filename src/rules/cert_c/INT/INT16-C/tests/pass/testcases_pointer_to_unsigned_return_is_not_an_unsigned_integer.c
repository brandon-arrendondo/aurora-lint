/*
 * Rule: INT16-C
 * Source: custom
 * Status: PASS - should NOT trigger INT16-C violation
 * Description: `const unsigned char *f(...)` returns a pointer; the
 * `unsigned` describes the pointee, not an unsigned integer result. A
 * substring match on the return type text read sqlite's vdbeapi.c text
 * accessor as an unsigned-integer function, then matched its pointer-typed
 * `val` to an unrelated signed `val` elsewhere in the file. Both halves are
 * shown here: the pointer return, and the colliding name.
 */

struct value {
    const unsigned char *z;
    int n;
};

int value_length(struct value *v) {
    int val = v->n;
    return val;
}

const unsigned char *value_text(struct value *v) {
    const unsigned char *val = v->z;
    return val;
}

unsigned int *first_slot(unsigned int *table, int idx) {
    unsigned int *val = table + idx;
    return val;
}
