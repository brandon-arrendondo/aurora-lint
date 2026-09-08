/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. Every argument past a
 * scanf-family format string is an output the call may initialize -- BUT
 * scanf's return count controls how many fields were actually matched, so
 * a partial match leaves later outputs untouched. The fixture demonstrates
 * the correct pattern: check the return before reading the output. An
 * unchecked scanf followed by a use of its output is task 1065's real bug
 * (see fail/testcases_scanf_unchecked_return.c).
 */
#include <stdio.h>

void use_int(int v);
void use_str(const char *s);

void scalar_output(const char *s) {
    int x;
    if (sscanf(s, "%d", &x) == 1) {
        use_int(x);
    }
}

/* A bare char array at an output position: the buffer the call fills, not a
   content read of it. */
void array_output(const char *s) {
    char name[32];
    if (sscanf(s, "%31s", name) == 1) {
        use_str(name);
    }
}

/* scanf: format at argument 0, outputs from 1. */
void stdin_output(void) {
    int y;
    if (scanf("%d", &y) == 1) {
        use_int(y);
    }
}

/* fscanf: stream at 0, format at 1, outputs from 2. */
void stream_output(FILE *fp) {
    int z;
    if (fscanf(fp, "%d", &z) == 1) {
        use_int(z);
    }
}
