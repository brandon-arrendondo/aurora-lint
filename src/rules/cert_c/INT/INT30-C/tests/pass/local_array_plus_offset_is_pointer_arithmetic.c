/*
 * Rule: INT30-C
 * Source: real-world (hostap src/crypto/aes-ccm.c:51 `aad_buf + 2 + aad_len`)
 * Status: PASS - Should NOT trigger INT30-C violation
 * Reason: `aad_buf` is a local array, so `aad_buf + 2 + aad_len` is pointer
 *         arithmetic, not an unsigned integer sum that can wrap. Same gap as
 *         INT32-C's: the shared pointer_typing gate saw the type map's
 *         "u8" for the array and let it through. Resolving the occurrence
 *         to its array declarator (ADR-0006) closes it for every consumer of
 *         the gate at once.
 */

#include <string.h>

typedef unsigned char u8;

void ccm_aad(const u8 *aad, size_t aad_len, u8 *out)
{
    u8 aad_buf[2 * 16];

    aad_buf[0] = (u8)(aad_len >> 8);
    aad_buf[1] = (u8)(aad_len & 0xff);
    memcpy(aad_buf + 2, aad, aad_len);
    memset(aad_buf + 2 + aad_len, 0, 4);
    memcpy(out, aad_buf, sizeof(aad_buf));
}
