/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: main zeroes RLIMIT_CORE conditionally and only after login() has used the password.
 */
#include <sys/resource.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
static void login(const char *typed) {
    char *pw = strdup(typed);
    if (!pw) return;
    crypt(pw, "ab");
    free(pw);
}
static void harden(void) {
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);
}
int main(int argc, char **argv) {
    login(argv[1]);
    if (argc > 5) harden();
    return 0;
}
