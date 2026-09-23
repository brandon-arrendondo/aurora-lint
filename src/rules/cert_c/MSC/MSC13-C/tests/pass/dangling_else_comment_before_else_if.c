/*
 * Rule: MSC13-C
 * Source: curl lib/vtls/openssl.c ossl_connect_step2
 * Status: PASS - Should NOT trigger MSC13-C violation
 *
 * `result` is set on every arm of this if/else-if/else chain and read via
 * the final `return result;`. A comment explaining why the
 * `SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED` guard exists sits between the
 * `#ifdef` and the real `else if` it wraps -- aurora-lint's dangling-else
 * preprocessor repair pass previously looked only at the guarded block's
 * very first line to decide whether it starts with `else`, so a leading
 * comment defeated that detection entirely. The guard's directives were
 * left in place, corrupting the whole chain's parse (and, downstream,
 * hiding every write/read inside it -- including the final read of
 * `result` this test exists to confirm stays visible).
 */
int f(int lib, int reason) {
    int result;
    if ((lib == 1) && (reason == 1)) {
        result = 10;
    }
#ifdef SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED
    /* only available on newer builds, per upstream's own comment */
    else if ((lib == 1) && (reason == 2)) {
        result = 20;
    }
#endif
    else {
        result = 30;
    }
    return result;
}
