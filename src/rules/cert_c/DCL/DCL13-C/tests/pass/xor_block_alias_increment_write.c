/*
 * Rule: DCL13-C
 * Status: PASS - Should NOT trigger DCL13-C violation
 */

/*
 * Reason (task 391, hostap's aes-ccm.c/aes-gcm.c `xor_aes_block`/
 * `xor_block`): `dst` is genuinely modified through the cast alias `d` via
 * `*d++ ^= *s++;` -- a pointer-increment-assign write. Previously
 * `is_write_through_param`'s `pointer_expression` case only matched a bare
 * identifier operand (`*param`), so `*d++` (whose operand is the
 * `update_expression` `d++`, not a bare identifier) went unrecognized as a
 * write.
 */

typedef unsigned int u32;
typedef unsigned char u8;

static void xor_aes_block(u8 *dst, const u8 *src)
{
    u32 *d = (u32 *) dst;
    u32 *s = (u32 *) src;
    *d++ ^= *s++;
    *d++ ^= *s++;
    *d++ ^= *s++;
    *d++ ^= *s++;
}

/*
 * Reason (task 391, hostap's aes-gcm.c `inc32`): `block` is genuinely
 * modified via `WPA_PUT_BE32(block + AES_BLOCK_SIZE - 4, val)` -- an
 * unknown (non-read-only) call receiving a pointer-arithmetic offset
 * (`block + K1 - K2`) from the parameter, which still targets memory
 * `block` points to. Previously only a bare `param`/`(cast)param` argument
 * counted as "param passed to a modifying call"; an offset expression did
 * not.
 */

#define AES_BLOCK_SIZE 16
void WPA_PUT_BE32(u8 *pos, u32 val);
u32 WPA_GET_BE32(const u8 *pos);

static void inc32(u8 *block)
{
    u32 val;
    val = WPA_GET_BE32(block + AES_BLOCK_SIZE - 4);
    val++;
    WPA_PUT_BE32(block + AES_BLOCK_SIZE - 4, val);
}
