/*
 * Rule: EXP34-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger EXP34-C violation
 * Description: REQUIRE(p) calls this file's own static die(), which never returns, when p is null, so p is non-null after it.
 *
 * Settings: stdlib_noreturn=true
 * The library contract that exit never returns is held on under every
 * preset; what this fixture tests is that a file's own static helper still
 * makes its check macro a guard.
 */

#include <stdio.h>
#include <stdlib.h>

static void die(const char *m) {
    fputs(m, stderr);
    exit(1);
}

#define REQUIRE(x) do { if (!(x)) die("req"); } while (0)

void f(void) {
    char *p = malloc(4);
    REQUIRE(p);
    p[0] = 1;
    free(p);
}
