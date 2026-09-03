/*
 * Rule: MSC13-C
 * Source: curl lib/curl_addrinfo.c curl_dbg_getaddrinfo (task 751)
 * Status: PASS - Should NOT trigger MSC13-C violation
 *
 * `res` is declared three times, once per mutually exclusive
 * #ifdef/#elif/#else branch, in the same scope. A read after the group
 * (`if (res == 0)`) resolves textually to only the LAST declaration
 * (find_enclosing_declaration_for_identifier picks the nearest preceding
 * one), so the first two alternatives previously looked "never read" even
 * though exactly one of the three ever compiles and it is always the one
 * read below. Same-scope, same-name declarations split by
 * #if/#ifdef/#elif/#else must be treated as one liveness entity.
 */

int f(int a, int b) {
#ifdef USE_LWIPSOCK
  int res = a;
#elif defined(USE_FAKE_GETADDRINFO)
  int res = b;
#else
  int res = a + b;
#endif
  if (res == 0)
    return 1;
  return 0;
}
