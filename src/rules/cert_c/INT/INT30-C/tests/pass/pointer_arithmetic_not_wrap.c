/*
 * Rule: INT30-C
 * Source: task 914 (hostap eap_eke_common.c:663, sel4 ieee802_11_eht.c:2040)
 * Status: PASS - Should NOT trigger INT30-C violation
 * Reason: `prot + prot_len - icv_len` is pointer arithmetic and
 *         `pos - orig_pos` a ptrdiff_t computation. Neither is unsigned
 *         integer wrap; forming an out-of-bounds pointer is ARR30-C's.
 */

#include <stddef.h>
#include <stdlib.h>

unsigned char *icv_position(unsigned char *prot) {
    size_t prot_len = (size_t)atoi(getenv("P"));
    size_t icv_len = (size_t)atoi(getenv("I"));
    return prot + prot_len - icv_len;
}

size_t advance(unsigned char *pos, unsigned char *orig_pos, size_t pos_len) {
    pos_len += pos - orig_pos;
    return pos_len;
}

/* A file-scope pointer is in scope for every function but in no local
   type map -- it must still read as a pointer. */
static unsigned char *cursor;

unsigned char *bump(void) {
    size_t n = (size_t)atoi(getenv("N"));
    return cursor + n;
}
