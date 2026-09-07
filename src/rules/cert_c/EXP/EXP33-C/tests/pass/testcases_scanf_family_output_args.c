/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. Every argument past a
 * scanf-family format string is an output the call initializes. The family is
 * variadic, so it has no fixed output index to list, and listing it with an
 * empty one suppressed the `&var` credit any unlisted function already gets
 * (task 1029).
 */
#include <stdio.h>

void use_int(int v);
void use_str(const char *s);

void scalar_output(const char *s) {
    int x;
    sscanf(s, "%d", &x);
    use_int(x);
}

/* A bare char array at an output position: the buffer the call fills, not a
   content read of it. */
void array_output(const char *s) {
    char name[32];
    sscanf(s, "%31s", name);
    use_str(name);
}

/* scanf: format at argument 0, outputs from 1. */
void stdin_output(void) {
    int y;
    scanf("%d", &y);
    use_int(y);
}

/* fscanf: stream at 0, format at 1, outputs from 2. */
void stream_output(FILE *fp) {
    int z;
    fscanf(fp, "%d", &z);
    use_int(z);
}
