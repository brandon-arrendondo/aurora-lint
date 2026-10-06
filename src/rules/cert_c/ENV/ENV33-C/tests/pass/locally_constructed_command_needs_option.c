/*
 * Rule: ENV33-C
 * Source: regression
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * The command is built inside the function from a literal, and the function
 * reads no untrusted input and takes no pointer, so no untrusted data can
 * reach system(). The default policy does not report it
 * (env33_locally_constructed_command_allowed). The strict policy reports the
 * call as CERT's page is written: a command processor is invoked (ADR-0001).
 */

#include <stdlib.h>
#include <string.h>

void list_directory(void)
{
    char buf[32];
    strcpy(buf, "ls -la");
    system(buf);
}
