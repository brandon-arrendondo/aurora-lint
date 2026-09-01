/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation.
 * `ldap_option`/`ldap_ca` are declared but never assigned on the `#else`
 * branch (the real assignment is under the opposite `#ifdef LDAP_OPT_X_TLS`
 * guard); the standard `(void)x;` idiom immediately discards them without
 * ever reading their content -- GCC/Clang special-case a bare-identifier
 * `(void)` cast to skip the load entirely, which is exactly why this
 * convention exists (to silence "unused variable" warnings without a real
 * read). Task 461 category 10; curl's ldap.c/mbedtls.c.
 */
int fail(void);

int f(void) {
    int ldap_option;
    char *ldap_ca;

#ifdef LDAP_OPT_X_TLS
    ldap_option = 1;
    ldap_ca = "ca";
#else
    (void)ldap_option;
    (void)ldap_ca;
    return fail();
#endif
    return ldap_option;
}
