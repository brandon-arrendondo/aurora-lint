/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: The array's initializer writes the secret before any lock can run.
 */
#include <sys/mman.h>
#include <crypt.h>
const char *h(const char *salt, char c) {
    char pw[8] = { c, c, c, c, 0 };
    mlock(pw, sizeof pw);
    return crypt(pw, salt);
}
