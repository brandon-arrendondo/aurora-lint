/*
 * Rule: INT30-C
 * Source: real-world (hostap wpa_supplicant `wpa_s->sme.assoc_req_ie + ...`)
 * Status: PASS - Should NOT trigger INT30-C violation
 * Reason: `assoc_req_ie` is an array member of an anonymous struct that is
 *         itself a member (`sme`) and sits inside an `#ifdef` of the body, so
 *         `s->sme.assoc_req_ie + n` is pointer arithmetic, not an unsigned
 *         sum. The struct's own field-type table cannot name the anonymous
 *         struct or see into the `#ifdef`; the member shapes are filed under
 *         `supplicant.sme` for exactly this.
 */

#include <stddef.h>

typedef unsigned char u8;

struct supplicant {
    int id;
#ifdef CONFIG_SME
    struct {
        u8 assoc_req_ie[1500];
        size_t assoc_req_ie_len;
    } sme;
#endif
    struct {
        struct {
            u8 deep[16];
        } inner;
    } outer;
};

u8 *append_ie(struct supplicant *s, size_t extra)
{
    return s->sme.assoc_req_ie + extra;
}

u8 *append_deep(struct supplicant *s, size_t extra)
{
    return s->outer.inner.deep + extra;
}
