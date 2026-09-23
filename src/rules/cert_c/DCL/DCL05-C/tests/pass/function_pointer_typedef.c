/*
 * Rule: DCL05-C
 * Source: wiki Exceptions ("Function pointer types are an exception to this
 *         recommendation"); real-world mbedtls bignum_mod.h mbedtls_mpi_modp_fn,
 *         pk_wrap.h mbedtls_pk_rsa_alt_decrypt_func, an earlier fix
 * Status: PASS - Should NOT trigger DCL05-C violation
 */

#include <stddef.h>

typedef int (*modp_fn)(unsigned long *X, size_t X_limbs);
typedef int (*rsa_alt_decrypt_func)(void *ctx, size_t *olen,
                                    const unsigned char *input,
                                    unsigned char *output, size_t output_max_len);
typedef void *(*alloc_fn)(size_t bytes);

int apply(modp_fn f, unsigned long *x, size_t n)
{
    return f(x, n);
}
