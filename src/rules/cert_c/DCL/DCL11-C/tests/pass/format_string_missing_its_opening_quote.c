/*
 * Rule: DCL11-C
 * Status: PASS - Should NOT trigger DCL11-C violation
 *
 * The format string lost its opening quote, so its closing one is a lone
 * quote opening a literal the line never closes. There is no format string
 * to read, and the rule must not fail on it.
 */

#include <stdio.h>

void name_file(char *buf, const char *name)
{
    sprintf(buf, %.123s.txt", name);
}
