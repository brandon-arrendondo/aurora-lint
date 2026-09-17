/*
 * Rule: FIO47-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO47-C violation
 *
 * Guards against overcorrecting the get_data_arguments() skip-count fix:
 * a genuine type mismatch among snprintf's real (post buf/size/fmt)
 * arguments must still be detected.
 */
#include <stdio.h>

void bad_snprintf(char *buf, size_t size) {
    const char *name = "example";
    snprintf(buf, size, "%d", name);
}
