/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to the same array
 * Status: PASS
 * Reason: A cursor and its bound arrive as two separate parameters, so nothing
 *         inside these functions can tell whether they share an object -- and
 *         no call site here says they do not. Distilled from hostap's
 *         '(u8 **pos, u8 *end)' buffer writers and curl's ASN.1 '(beg, end)'
 *         range walkers, where every caller does 'pos = buf; end = buf + len;'
 *         one frame up.
 */

#include <stddef.h>

typedef unsigned char u8;

/* Cursor passed by address, bound passed by value: the whole population of
 * 'end - *pos' bounds checks. */
int write_tlv(u8 **pos, u8 *end, u8 type, size_t len)
{
    if (end - *pos < (long)(2 + len))
        return -1;
    *(*pos)++ = type;
    *(*pos)++ = (u8)len;
    return 0;
}

/* Two plain pointer parameters delimiting one range. */
size_t range_length(const u8 *beg, const u8 *end)
{
    if (beg >= end)
        return 0;
    return (size_t)(end - beg);
}

/* The same shape, walked in a loop. */
int count_zeros(const u8 *pos, const u8 *end)
{
    int zeros = 0;

    while (pos < end) {
        if (*pos == 0)
            zeros++;
        pos++;
    }
    return zeros;
}
