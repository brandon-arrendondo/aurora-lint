/*
 * Rule: EXP33-C
 * Source: testcases (mbedtls mbedtls_ecp_point_init shape)
 * Status: PASS - Should NOT trigger EXP33-C violation.
 * `point_init` never reads `pt` at all: every `pt->` occurrence is the
 * operand of an address-of expression (`&pt->x`, `&pt->y`, `&pt->z`),
 * handing each field's address to `field_init`, which writes through it.
 * The old dereferences_params text scan matched the bare substring
 * `pt->` regardless of the leading `&`, so `point_init` looked like it
 * read `pt` without ever writing it and was wrongly classified read-only
 * on its own output parameter -- exactly the mbedtls_ecp_point_init /
 * mbedtls_ecp_keypair_init / mbedtls_aes_xts_init shape. Companion to
 * fail/testcases_crossfile_readonly_deref.c, which has a genuine read
 * (`int local = *ptr;`, no leading `&`) and must stay flagged.
 */

struct big_num {
    int limbs;
};

struct point {
    struct big_num x;
    struct big_num y;
    struct big_num z;
};

static void field_init(struct big_num *n) {
    n->limbs = 0;
}

void point_init(struct point *pt) {
    field_init(&pt->x);
    field_init(&pt->y);
    field_init(&pt->z);
}

void f(void) {
    struct point p;
    point_init(&p);
}
