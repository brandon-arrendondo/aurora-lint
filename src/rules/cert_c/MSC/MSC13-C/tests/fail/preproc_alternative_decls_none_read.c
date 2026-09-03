/*
 * Rule: MSC13-C
 * Source: task 751 companion regression
 * Status: FAIL - Should trigger MSC13-C violation
 *
 * Companion to preproc_alternative_decls_one_read.c (pass): grouping
 * same-scope, same-name preprocessor-alternative declarations into one
 * liveness entity must not suppress a genuine violation when NONE of the
 * alternatives is ever read.
 */

void f(int a, int b) {
#ifdef USE_LWIPSOCK
  int res = a;
#elif defined(USE_FAKE_GETADDRINFO)
  int res = b;
#else
  int res = a + b;
#endif
}
