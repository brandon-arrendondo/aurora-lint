/*
 * Rule: DCL11-C
 * Status: PASS - Should NOT trigger DCL11-C violation
 *
 * The function body lost its opening brace, and the parser reads the call's
 * format string as a lone quote. There is no format string to read, and the
 * rule must not fail on it.
 */

void handler(int sig)
    printf("signal %d\n", sig);
    void *p = malloc(100);
