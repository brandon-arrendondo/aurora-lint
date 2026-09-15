/*
 * Rule: API00-C
 * Source: mbedtls include/mbedtls/aes.h (task 1171)
 * Status: PASS - Should NOT trigger API00-C violation
 * Description: The function's own doc comment states that `ctx` must be
 * initialized and `key` must be a readable buffer -- the published contract
 * places validation on the caller, the "validate on one side of the
 * interface" discipline written down. Only the function's own statement
 * counts (never an inference from its callers, task 644), and only explicit
 * wording: see fail/documented_without_precondition.c.
 */

typedef struct { unsigned int rk[60]; int nr; } aes_context;

/**
 * \brief          This function sets the encryption key.
 *
 * \param ctx      The AES context to which the key should be bound.
 *                 It must be initialized.
 * \param key      The encryption key.
 *                 This must be a readable buffer of size \p keybits bits.
 * \param keybits  The size of data passed in bits.
 *
 * \return         \c 0 on success.
 */
int aes_setkey_enc(aes_context *ctx, const unsigned char *key, unsigned int keybits)
{
    ctx->nr = (int) keybits / 32;
    ctx->rk[0] = key[0];
    return 0;
}
