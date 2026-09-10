/*
 * Rule: INT16-C
 * Source: custom
 * Status: FAIL - SHOULD trigger INT16-C violation
 * Description: The positive side of the destination check: a signed value
 * proven negative stored into an unsigned object that is resolved from the
 * declaration in scope -- a typedef'd unsigned scalar, the pointee of an
 * `unsigned int *`, an element of an unsigned array, and an unsigned struct
 * field. Each is the twin of a shape tests/pass/
 * testcases_signed_destination_is_not_unsigned_by_absence.c refuses to
 * report when the destination is signed.
 */

typedef unsigned int u32;

struct counters {
    unsigned int errors;
};

void store_typedef(int rc) {
    u32 code;
    if (rc < 0) {
        code = rc;
    }
    (void)code;
}

void store_pointee(unsigned int *pu, int rc) {
    if (rc < 0) {
        *pu = rc;
    }
}

void store_element(unsigned int *slots, int rc) {
    if (rc < 0) {
        slots[0] = rc;
    }
}

void store_field(struct counters *c, int rc) {
    if (rc < 0) {
        c->errors = rc;
    }
}
