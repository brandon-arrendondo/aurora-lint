/*
 * Rule: FIO21-C
 * Source: regression
 * Status: FAIL - Should trigger FIO21-C violation
 *
 * mktemp() is called through a project function-like macro, which the scan
 * sees only as an invocation of SCRATCH_NAME. Its expansion is the call.
 */

#include <stdlib.h>

#define SCRATCH_NAME(t) mktemp(t)

char *scratch_name(char *tmpl) {
    return SCRATCH_NAME(tmpl);
}
