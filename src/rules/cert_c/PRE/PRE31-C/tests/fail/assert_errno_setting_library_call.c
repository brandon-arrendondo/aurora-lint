/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: strtol sets errno on overflow (C11 7.22.1.4p8), and CERT
 * PRE31-C-EX1 counts changing errno as a side effect. Under the strict
 * preset the library contract is withdrawn and the call is unknown, which
 * strict reports too.
 */

#include <assert.h>
#include <stdlib.h>

void a(const char *s) {
    assert(strtol(s, NULL, 10) > 0);  // VIOLATION
}
