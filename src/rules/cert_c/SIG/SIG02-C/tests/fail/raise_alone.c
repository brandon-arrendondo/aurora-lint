/*
 * Rule: SIG02-C
 * Source: synthetic
 * Status: FAIL - Should trigger SIG02-C violation
 *
 * A timer tick delivered by the program to itself, with the signal argument
 * parenthesized.
 */
#include <signal.h>

void tick(void)
{
    raise((SIGALRM));
}
