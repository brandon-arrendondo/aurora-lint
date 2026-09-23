/*
 * Rule: MEM01-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM01-C violation
 * Description: an assignment or declaration that reads the freed pointer
 * itself is still a use, even when an output-parameter call appears
 * elsewhere in the statement.
 */

#include <stdlib.h>

int fmt(char **out, const char *s);

void lhs_reads_freed_pointer(void) {
    char *cmd = malloc(8);
    free(cmd);
    cmd[0] = (char)fmt(&cmd, "x");
}

void initializer_reads_freed_pointer(void) {
    char *cmd = malloc(8);
    free(cmd);
    int n = cmd[0];
    (void)n;
}
