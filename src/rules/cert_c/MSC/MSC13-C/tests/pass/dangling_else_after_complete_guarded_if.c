/*
 * Rule: MSC13-C
 * Source: curl lib/vtls/openssl.c ossl_connect_step2 (task 1151/1193),
 *   SSL_ERROR_WANT_ASYNC/SSL_ERROR_WANT_RETRY_VERIFY guards
 * Status: PASS - Should NOT trigger MSC13-C violation
 *
 * `result` is set on the else branch and read via `return result;`.
 * Preceding branches (mirroring SSL_ERROR_WANT_READ/WRITE/ASYNC) each
 * return early, so `result` is never touched except by the else. The
 * guarded block right above the `else` (`#ifdef SSL_ERROR_WANT_RETRY_VERIFY
 * ... #endif`) is a *complete*, self-contained `if (...) { ... }` -- no
 * dangling else inside it at all -- so the existing leading/trailing-else
 * detection never had a reason to touch it. But the grammar still can't
 * attach the bare `else` right after `#endif` across that intervening
 * preprocessor-conditional sibling to the `if` it wraps, corrupting the
 * parse (and, downstream, hiding this function's `else`/`return result;`
 * from every analysis pass) exactly the same way a dangling fragment
 * would.
 */
int f(int detail) {
    int result;
    if (detail == 1) {
        return -1;
    }
#ifdef SSL_ERROR_WANT_RETRY_VERIFY
    if (detail == 2) {
        return -1;
    }
#endif
    else {
        result = 3;
    }
    return result;
}
