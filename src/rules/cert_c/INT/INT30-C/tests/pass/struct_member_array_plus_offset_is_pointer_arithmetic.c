/*
 * Rule: INT30-C
 * Source: real-world (hostap wpa_supplicant sme.c `wpa_s->sme.assoc_req_ie + ...`)
 * Status: PASS - Should NOT trigger INT30-C violation
 * Reason: `assoc_req_ie` is an array member, so `ie + n` is pointer
 *         arithmetic, not an unsigned integer sum that can wrap. The field-type
 *         table spells an array member by its element type (`u8`); the member's
 *         declarator shape says it is an array, and an array decays to a
 *         pointer here.
 */

#include <stddef.h>

typedef unsigned char u8;

struct sme {
    u8 assoc_req_ie[1500];
    size_t assoc_req_ie_len;
};

struct supplicant {
    struct sme sme;
};

u8 *append_ie(struct supplicant *wpa_s, size_t extra)
{
    return wpa_s->sme.assoc_req_ie + wpa_s->sme.assoc_req_ie_len + extra;
}

u8 *direct(struct sme *sme, size_t n)
{
    return sme->assoc_req_ie + n;
}
