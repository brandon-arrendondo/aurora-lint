/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: rlim_cur is zeroed on one branch and set to RLIM_INFINITY on the other, so the setrlimit call does not always disable core dumps.
 */
#include <sys/resource.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
static void login(const char *typed) { char *pw = strdup(typed); if (!pw) return; crypt(pw, "ab"); free(pw); }
int main(int argc, char **argv) {
    struct rlimit rl;
    if (argc > 9) rl.rlim_cur = 0; else rl.rlim_cur = RLIM_INFINITY;
    rl.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &rl);
    login(argv[1]);
    return 0;
}
