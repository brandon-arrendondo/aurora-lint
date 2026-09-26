/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: main zeroes RLIMIT_CORE with a designated initializer before calling the function that uses the password.
 */
#include <sys/resource.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
static void login(const char *typed) { char *pw = strdup(typed); if (!pw) return; crypt(pw, "ab"); free(pw); }
int main(int argc, char **argv) {
    struct rlimit rl = { .rlim_cur = 0, .rlim_max = 0 };
    if (setrlimit(RLIMIT_CORE, &rl) != 0) return 1;
    login(argv[1]);
    return 0;
}
