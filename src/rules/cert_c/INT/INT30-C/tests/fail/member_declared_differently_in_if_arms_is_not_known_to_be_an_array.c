/*
 * Rule: INT30-C
 * Source: testcases
 * Status: FAIL - Should trigger INT30-C violation
 * Description: Companion to pass/struct_member_array_plus_offset_is_pointer_arithmetic.c
 * and pass/anonymous_struct_member_array_under_ifdef_plus_offset.c. A member
 * declared as an array in one arm of a preprocessor conditional and as an
 * integer in the other is not known to be an array: the arms disagree and the
 * rule must not pick one, so the unsigned sum is still reported. The same
 * holds for a path through a member that is an anonymous struct in one arm
 * and a named struct in the other.
 */

#include <stddef.h>

struct plain {
#ifdef WIDE
    size_t ie;
#else
    unsigned char ie[8];
#endif
};

struct nested {
#ifdef INLINE_SME
    struct {
        unsigned char ie[8];
    } sme;
#else
    struct sme_t {
        size_t ie;
    } sme;
#endif
};

size_t plain_member(struct plain *p, size_t n)
{
    /* VIOLATION: `ie` is an array or an integer, depending on the arm */
    return p->ie + n;
}

size_t nested_member(struct nested *s, size_t n)
{
    /* VIOLATION: `sme.ie` is an array or an integer, depending on the arm */
    return s->sme.ie + n;
}
