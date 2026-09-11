/*
 * Rule: DCL06-C
 * Source: bmdb-757
 * Status: PASS - comparison against a well-known version macro
 * Description: a literal compared directly against a library/platform
 * version macro (OPENSSL_VERSION_NUMBER, _MSC_VER, etc.) is a version-check
 * idiom, not hidden program logic -- the macro's own name already carries
 * the meaning a symbolic constant would add.
 */

#define OPENSSL_VERSION_NUMBER 0x30000000L

int check_version(void) {
    if (OPENSSL_VERSION_NUMBER < 0x30000000L) {
        return 0;
    }
    return 1;
}
