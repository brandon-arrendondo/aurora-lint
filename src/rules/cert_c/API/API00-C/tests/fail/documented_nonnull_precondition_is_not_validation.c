/*
 * Rule: API00-C
 * Source: mbedtls include/mbedtls/aes.h
 * Status: FAIL - Should trigger API00-C violation
 * Description: The function's own doc comment says `ctx` must be
 * initialized and `key` must be a readable buffer, but C has no contract
 * language for a project's own functions: the comment states an intended
 * precondition, and nothing makes a caller honour it (ADR-0011). The
 * parameters are dereferenced unvalidated, so they are reported like any
 * others.
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
