/*
 * Rule: INT30-C
 * Source: testcases
 * Status: FAIL - Should trigger INT30-C violation
 * Description: Reversed-arms companion to
 * member_declared_differently_in_if_arms_is_not_known_to_be_an_array.c. Here
 * the named-type `sme` arm comes first and the anonymous arm second; the
 * anonymous arm's `sme.ie` array must not survive as the answer, whatever the
 * order of the arms.
 */

#include <stddef.h>

struct nested {
#ifndef INLINE_SME
    struct sme_t {
        size_t ie;
    } sme;
#else
    struct {
        unsigned char ie[8];
    } sme;
#endif
};

size_t nested_member(struct nested *s, size_t n)
{
    /* VIOLATION: `sme.ie` is an integer or an array, depending on the arm */
    return s->sme.ie + n;
}
