/*
 * Rule: PRE31-C
 * Source: real-world (mbedtls library/ssl_ciphersuites.c, 10 sites)
 * Status: PASS - Should NOT trigger PRE31-C violation
 *
 * `defined(X)` in a directive condition is a preprocessor operator, not an
 * invocation of a function-like macro, so there is no argument list to carry a
 * side effect. When tree-sitter absorbs the directive into an ERROR node it
 * reparses as a call_expression and the condition's other operands read as its
 * arguments. See ADR-0008.
 */

#define KEY_EXCHANGE_RSA_ENABLED 1

#if defined(KEY_EXCHANGE_RSA_ENABLED)

#if (defined(HAVE_GCM) && defined(CAN_SHA384))
static const int ciphersuite_rsa_gcm_sha384 = 1;
#endif

#endif

int h(void)
{
    return 0;
}
