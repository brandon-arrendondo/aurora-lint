/*
 * Rule: MSC13-C
 * Source: mbedtls library/psa_crypto.c psa_key_derivation_abort
 * Status: PASS - No violation
 *
 * The first arm of the chain is empty, so `status = PSA_SUCCESS` reaches
 * `return status` when `alg == 0`. The chain is spliced across feature
 * guards (`} else` right before `#endif`); the pre-parse pass joins it so
 * the CFG sees one if/else-if statement rather than a dangling else.
 */

#define PSA_SUCCESS 0
#define PSA_ERROR_BAD_STATE -137
#define HAVE_HKDF
#define HAVE_PRF

int abort_hkdf(void);
int abort_prf(void);

int derivation_abort(int alg)
{
    int status = PSA_SUCCESS;

    if (alg == 0) {
        /* nothing to do */
    } else
#if defined(HAVE_HKDF)
    if (alg == 1) {
        status = abort_hkdf();
    } else
#endif
#if defined(HAVE_PRF)
    if (alg == 2) {
        status = abort_prf();
    } else
#endif
    {
        status = PSA_ERROR_BAD_STATE;
    }

    return status;
}
