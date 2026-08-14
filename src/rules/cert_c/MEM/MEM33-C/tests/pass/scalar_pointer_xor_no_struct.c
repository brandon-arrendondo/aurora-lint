/*
 * Rule: MEM33-C
 * Status: PASS - Should NOT trigger MEM33-C violation
 */

/*
 * Reason: `*d++ ^= *s++;` dereferences plain `u32 *` pointers -- no struct,
 * let alone one with a flexible array member, is anywhere in sight (task
 * 391, hostap's aes-ccm.c/aes-gcm.c `xor_aes_block`/`xor_block`). Previously
 * `is_flexible_struct_dereference` treated *any* pointer dereference as a
 * flexible-array-struct instance, misfiring here.
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
