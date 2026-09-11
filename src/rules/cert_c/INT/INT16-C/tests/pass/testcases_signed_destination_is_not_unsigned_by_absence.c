/*
 * Rule: INT16-C
 * Source: custom
 * Status: PASS - should NOT trigger INT16-C violation
 * Description: An assignment target is reported only when it is SHOWN to be
 * an unsigned integer object. A previous version reported any target whose
 * name was absent from its signed-variable map, so `*pi = i` through an
 * `int *pi` (sqlite fts5_buffer.c) and `u->certverifyresult = rc` into a
 * `long` field (curl gtls.c) were both reported as unsigned destinations.
 * Neither is: the pointee is `int`, the field is `long`.
 */

struct urldata {
    long certverifyresult;
    int status;
};

void store_index(int *pi, int i) {
    if (i < 0) {
        *pi = i;
    }
}

void store_result(struct urldata *u, int rc) {
    if (rc < 0) {
        u->certverifyresult = rc;
        u->status = rc;
    }
}

void store_into_array(int *slots, int rc) {
    if (rc < 0) {
        slots[0] = rc;
    }
}

void store_into_unknown(void *opaque, int rc) {
    long *dst = (long *)opaque;
    if (rc < 0) {
        *dst = rc;
    }
}
