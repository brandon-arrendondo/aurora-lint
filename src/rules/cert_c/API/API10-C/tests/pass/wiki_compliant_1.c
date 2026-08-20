/*
 * Rule: API10-C
 * Source: wiki
 * Status: PASS - Should NOT trigger API10-C violation
 */

int tls_connect_by_name(const char *host, int port, int option_bitmask);
#define TLS_DEFAULT_OPTIONS 0
#define TLS_DISABLE_HOST_VALIDATION 0x0001  // use rarely, subject to man-in-the-middle attack
#define TLS_ENABLE_V1_0 0x0002
#define TLS_ENABLE_V1_1 0x0004
