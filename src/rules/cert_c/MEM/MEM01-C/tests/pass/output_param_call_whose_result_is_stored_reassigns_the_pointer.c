/*
 * Rule: MEM01-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM01-C violation
 * Description: `cmd` is freed and then rebound by an output-parameter call
 * (`fmt(&cmd, ...)`) whose return value is stored, declared, returned or
 * cast away rather than discarded. The call writes a fresh pointer through
 * `&cmd`, so the old value is never read. Modeled on valkey-benchmark's
 * default suite, where each test block does
 * `len = valkeyFormatCommand(&cmd, ...); ...; free(cmd);` inside one
 * do-while loop.
 */

#include <stdlib.h>

int fmt(char **out, const char *s);
void use(char *p, int n);

void stored_result(int a, int b, int loop) {
    char *cmd;
    int len;
    do {
        if (a) {
            len = fmt(&cmd, "x");
            use(cmd, len);
            free(cmd);
        }
        if (b) {
            len = fmt(&cmd, "y");
            use(cmd, len);
            free(cmd);
        }
    } while (loop);
}

void compound_assigned_result(int a) {
    char *cmd;
    int total = 0;
    total += fmt(&cmd, "x");
    free(cmd);
    if (a) {
        total += fmt(&cmd, "y");
        use(cmd, total);
        free(cmd);
    }
}

void declared_result(int a) {
    char *cmd;
    int first = fmt(&cmd, "x");
    use(cmd, first);
    free(cmd);
    if (a) {
        int second = fmt(&cmd, "y");
        use(cmd, second);
        free(cmd);
    }
}

void cast_away_result(void) {
    char *cmd;
    (void)fmt(&cmd, "x");
    free(cmd);
    (void)fmt(&cmd, "y");
    free(cmd);
}

int returned_result(void) {
    char *cmd;
    fmt(&cmd, "x");
    free(cmd);
    return fmt(&cmd, "y");
}
