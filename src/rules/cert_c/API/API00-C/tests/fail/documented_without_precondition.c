/*
 * Rule: API00-C
 * Source: mbedtls include/mbedtls/aes.h
 * Status: FAIL - Should trigger API00-C violation
 * Description: A doc comment that merely describes a pointer parameter
 * ("The AES context to use") states no precondition, so the caller-side
 * contract that pass/documented_nonnull_precondition.c relies on is not
 * there and the unguarded dereference is reported.
 */

typedef struct { unsigned int rk[60]; int nr; } aes_context;

/**
 * \brief          Internal AES block encryption function.
 *
 * \param ctx      The AES context to use for encryption.
 * \param input    The plaintext block.
 * \param output   The output (ciphertext) block.
 *
 * \return         \c 0 on success.
 */
int internal_aes_encrypt(aes_context *ctx, const unsigned char input[16], unsigned char output[16])
{
    output[0] = input[0] ^ (unsigned char) ctx->rk[0];
    return 0;
}
