/*
 * Rule: INT33-C
 * Source: aurora_lint 1284 (mbedtls library/x509_crt.c:2708,2711)
 * Status: PASS - Should NOT trigger INT33-C violation
 *
 * The `/` in a header path is a path separator, not a division operator, and
 * nothing is evaluated on a preprocessor directive line at run time. When
 * tree-sitter absorbs the directive into an ERROR node this reparsed as
 * "division by 'socket'". See ADR-0008.
 */

#if defined(__has_include)
#if __has_include(<sys/socket.h>)
#include <sys/socket.h>
#endif
#if __has_include(<arpa/inet.h>)
#include <arpa/inet.h>
#endif
#endif

int g(int a, int b)
{
    if (b == 0) {
        return 0;
    }
    return a / b;
}
