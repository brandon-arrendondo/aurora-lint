/*
 * Rule: ENV33-C
 * Source: regression
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * The static sink takes the command as a pointer, but its only caller reads
 * no untrusted input and passes a command it built itself, so no untrusted
 * data reaches system(). The default policy does not report it
 * (env33_locally_constructed_command_allowed, through every caller). The
 * strict policy reports the call (ADR-0001).
 */

#include <stdlib.h>
#include <string.h>

static void run_command(const char *cmd)
{
    system(cmd);
}

void rotate_logs(void)
{
    char buf[64];
    strcpy(buf, "logrotate /etc/logrotate.conf");
    run_command(buf);
}
