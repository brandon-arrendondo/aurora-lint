/* Three non-static sinks: system() runs whatever command reaches each one
 * as a parameter. Whether it is flagged depends on every caller up the
 * chain, and on whether the scanned files are all of the callers there
 * are (the closed_program declaration, ADR-0011). */
#include <stdlib.h>

void run_fixed(char *cmd)
{
    system(cmd);
}

void run_by_pointer(char *cmd)
{
    system(cmd);
}

void run_arg(char *cmd)
{
    system(cmd);
}
