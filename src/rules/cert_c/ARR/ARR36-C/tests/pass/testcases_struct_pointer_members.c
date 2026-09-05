/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to the same array
 * Status: PASS
 * Reason: Every base below is a POINTER-typed struct member, so the path names
 *         a pointer rather than an object, and what it points AT is as
 *         unknowable inside these functions as a pointer parameter's target.
 *         Two such paths differing says nothing about whether the pointers
 *         walk one array. Distilled from curl lib/vtls/x509asn1.c (the 'beg'
 *         and 'end' of one ASN.1 element), sqlite src/vdbe.c ('pOut->z'
 *         against 'pC->aRow') and hostap's libtommath ('a->dp' against
 *         'b->dp').
 *
 *         An ARRAY-typed member is a different thing -- it IS storage of its
 *         own -- and still reports; see tests/fail/testcases_struct_arrays.c.
 */

#include <stddef.h>

struct asn1_element {
    const char *beg;
    const char *end;
};

struct cert {
    struct asn1_element tbs;
};

/* Two pointer members of one struct: the two ends of one element. */
size_t element_length(struct cert *cert)
{
    const char *beg = cert->tbs.beg;
    const char *end = cert->tbs.end;

    if (beg < end) {
        return (size_t)(end - beg);
    }
    return 0;
}

struct mem {
    char *z;
    int n;
};

struct cursor {
    unsigned char *aRow;
    unsigned int payloadSize;
};

/* Two pointer members of two different structs: whether they share an object
 * is unknown here, not known-distinct. */
int row_before_out(struct mem *pOut, struct cursor *pC)
{
    char *out = pOut->z;
    char *row = (char *)pC->aRow;

    return row < out;
}

typedef struct {
    int used;
    unsigned int *dp;
} mp_int;

/* The same member of two instances. */
int digits_between(mp_int *a, mp_int *b)
{
    unsigned int *ad = a->dp;
    unsigned int *bd = b->dp;

    if (ad > bd) {
        return (int)(ad - bd);
    }
    return 0;
}

int main(void)
{
    char body[16] = {0};
    unsigned int digits[4] = {0};
    struct cert c;
    struct mem m;
    struct cursor cur;
    mp_int x, y;

    c.tbs.beg = body;
    c.tbs.end = body + sizeof(body);
    m.z = body;
    m.n = (int)sizeof(body);
    cur.aRow = (unsigned char *)body;
    cur.payloadSize = (unsigned int)sizeof(body);
    x.dp = digits;
    x.used = 4;
    y.dp = digits;
    y.used = 4;

    return (int)element_length(&c) + row_before_out(&m, &cur) + digits_between(&x, &y);
}
