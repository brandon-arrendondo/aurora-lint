/*
 * Rule: ENV33-C
 * Source: regression
 * Status: FAIL - Should trigger ENV33-C violation under both presets
 *
 * The command is read from standard input, so untrusted data reaches
 * system(). env33_locally_constructed_command_allowed does not apply, and
 * both policies report the call.
 */

#include <stdio.h>
#include <stdlib.h>

void run_from_stdin(void)
{
    char buf[128];
    if (fgets(buf, sizeof buf, stdin) == NULL) {
        return;
    }
    system(buf);
}
