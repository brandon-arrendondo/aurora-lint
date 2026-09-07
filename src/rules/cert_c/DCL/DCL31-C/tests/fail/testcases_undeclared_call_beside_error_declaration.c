/*
 * Rule: DCL31-C
 * Source: task 1038
 * Status: FAIL - reading a declaration back out of an ERROR node must not
 * make the rule blind to a genuinely undeclared call in the same file.
 *
 * `sigaction` below is declared (in the shape task 1038 taught the collector
 * to read); `never_declared_anywhere` is not, and must still be reported.
 */

extern int sigaction (int sig, const void *act, void *oact) __THROW;

void f(void)
{
    sigaction(2, 0, 0);
    never_declared_anywhere(1);
}
