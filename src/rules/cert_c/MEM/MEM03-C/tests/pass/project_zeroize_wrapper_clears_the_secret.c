/*
 * Rule: MEM03-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM03-C violation
 * Description: mbedtls clears every secret through mbedtls_platform_zeroize,
 * whose body reaches memset only through a volatile function pointer (so
 * the compiler cannot elide the store -- exactly what CERT recommends), or
 * through explicit_bzero / memset_s / SecureZeroMemory under preprocessor
 * arms. hostap does the same with forced_memzero, and wraps memset in an
 * os_memset macro. None of these is named in the rule's clearing list, and
 * must not need to be: a wrapper is a clearer because its body clears its
 * parameter, a macro because its expansion does, and a wrapper of a
 * wrapper because the parameter is forwarded to one. Every secret below is
 * cleared on every path to its scope exit or free.
 */

#include <stdlib.h>
#include <string.h>

static void *(*const volatile memset_func)(void *, int, size_t) = memset;

void platform_zeroize(void *buf, size_t len) {
    if (len > 0) {
#if defined(HAS_EXPLICIT_BZERO)
        explicit_bzero(buf, len);
#elif defined(_WIN32)
        SecureZeroMemory(buf, len);
#else
        memset_func(buf, 0, len);
#endif
    }
}

static void forced_memzero(void *ptr, size_t len) {
    memset_func(ptr, 0, len);
}

static void wipe(void *p, size_t n) {
    platform_zeroize(p, n);
}

#define os_memset(s, c, n) memset(s, c, n)

int derive_secret(void) {
    unsigned char tmp_secret[32];
    unsigned char *password = malloc(64);
    if (password == NULL) {
        return -1;
    }
    tmp_secret[0] = 1;
    password[0] = 2;
    platform_zeroize(tmp_secret, sizeof(tmp_secret));
    forced_memzero(password, 64);
    free(password);
    return 0;
}

int stack_secret_via_wrapper_of_wrapper(void) {
    unsigned char shared_secret[48];
    shared_secret[0] = 1;
    wipe(shared_secret, sizeof(shared_secret));
    return 0;
}

int stack_secret_via_macro(void) {
    char passphrase[16];
    passphrase[0] = 'x';
    os_memset(passphrase, 0, sizeof(passphrase));
    return 0;
}
